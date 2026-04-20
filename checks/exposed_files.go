package checks

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(&ExposedFilesCheck{})
}

// exposedPaths is the wordlist of sensitive files/paths to probe.
var exposedPaths = []string{
	// Secrets & environment
	"/.env",
	"/.env.production",
	"/.env.backup",
	"/wp-config.php",
	"/config.php",
	"/database.yml",
	"/credentials.json",
	"/service-account.json",
	"/.aws/credentials",

	// Git exposure (full source code dump)
	"/.git/HEAD",
	"/.git/config",

	// Dumps & backups
	"/dump.sql",
	"/backup.sql",
	"/backup.zip",

	// Server info & PHP
	"/phpinfo.php",
	"/server-status",
	"/.htpasswd",

	// Spring Boot Actuator (RCE/data exposure)
	"/actuator/env",
	"/actuator/heapdump",

	// API schema exposure
	"/swagger.json",
	"/openapi.json",
	"/graphql",

	// Logs
	"/storage/logs/laravel.log",
	"/debug.log",

	// Admin panels
	"/wp-admin",
	"/phpmyadmin",
	"/admin",

	// Infrastructure files
	"/docker-compose.yml",
	"/.htaccess",
	"/web.config",
}

const (
	exposedFilesWorkers = 10
	exposedFilesTimeout = 8 * time.Second
)

// ExposedFile holds details about a discovered sensitive path.
type ExposedFile struct {
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	BodyPreview string `json:"body_preview,omitempty"` // first 200 chars
	Severity    string `json:"severity"`
}

// ExposedFilesCheck probes a wordlist of sensitive paths against the target.
type ExposedFilesCheck struct{}

func (e *ExposedFilesCheck) Name() string { return "exposed_files" }

func (e *ExposedFilesCheck) Run(target string, _ *http.Response) Result {
	base, err := buildBaseURL(target)
	if err != nil {
		return Result{
			CheckName: e.Name(),
			Passed:    false,
			Details: map[string]any{
				"error": fmt.Sprintf("invalid target URL: %v", err),
			},
		}
	}

	client := &http.Client{
		Timeout: exposedFilesTimeout,
		// Do NOT follow redirects — a 301/302 to /login is not a real hit.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	found := probeAll(client, base, exposedPaths, exposedFilesWorkers)
	passed := len(found) == 0

	return Result{
		CheckName: e.Name(),
		Passed:    passed,
		Details: map[string]any{
			"base_url":    base,
			"probed":      len(exposedPaths),
			"found":       found,
			"found_count": len(found),
		},
	}
}

// probeAll fans out probes across a worker pool and returns hits.
func probeAll(client *http.Client, base string, paths []string, workers int) []ExposedFile {
	type job struct {
		path string
	}

	jobs := make(chan job, len(paths))
	resultsCh := make(chan ExposedFile, len(paths))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if hit, ok := probe(client, base, j.path); ok {
					resultsCh <- hit
				}
			}
		}()
	}

	for _, p := range paths {
		jobs <- job{p}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var found []ExposedFile
	for hit := range resultsCh {
		found = append(found, hit)
	}
	return found
}

// probe performs a single GET request and returns an ExposedFile if it's a real hit.
func probe(client *http.Client, base, path string) (ExposedFile, bool) {
	fullURL := base + path

	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return ExposedFile{}, false
	}
	req.Header.Set("User-Agent", "waptly/1.0 (security posture scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return ExposedFile{}, false
	}
	defer resp.Body.Close()

	// Only treat 200 and 206 (partial content) as real hits.
	// 401/403 are interesting but noisy — see note below.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return ExposedFile{}, false
	}

	// Read a small preview of the body.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
	preview := strings.TrimSpace(string(bodyBytes))
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}

	// Skip false positives: custom 404 pages that return 200.
	if isSoftNotFound(resp, preview) {
		return ExposedFile{}, false
	}

	contentType := resp.Header.Get("Content-Type")

	return ExposedFile{
		Path:        path,
		StatusCode:  resp.StatusCode,
		ContentType: contentType,
		BodyPreview: preview,
		Severity:    assignSeverity(path),
	}, true
}

// isSoftNotFound tries to detect "soft 404s" — servers returning 200 for missing pages.
func isSoftNotFound(resp *http.Response, body string) bool {
	lower := strings.ToLower(body)

	// Very short body (< 10 chars) with no content type is likely empty catch-all.
	if len(body) < 10 && resp.Header.Get("Content-Type") == "" {
		return true
	}

	// Generic not-found indicators in body.
	notFoundPhrases := []string{
		"404", "not found", "page not found", "does not exist",
		"no such file", "error 404", "the page you",
	}
	for _, phrase := range notFoundPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}

	return false
}

// assignSeverity returns a severity rating based on the path.
func assignSeverity(path string) string {
	critical := []string{
		".env", "wp-config", "database.yml", "credentials",
		"secret", "heapdump", "passwd", ".htpasswd",
		"aws/credentials", "service-account", "actuator/env",
		"dump.sql", "backup.sql", "db_dump",
	}
	high := []string{
		".git/", "config.php", "config.yml", "settings.py",
		"application.properties", "docker-compose", "actuator",
		"swagger", "graphql", "phpinfo", "server-status",
		".htaccess", "web.config", "access.log", "error.log",
		"package.json", "requirements.txt", "Gemfile",
	}
	medium := []string{
		"admin", "phpmyadmin", "wp-admin", "wp-login",
		"backup.zip", "site.zip", ".gitignore", "Dockerfile",
		"openapi", "api-docs", "graphiql",
	}

	lower := strings.ToLower(path)
	for _, kw := range critical {
		if strings.Contains(lower, kw) {
			return "critical"
		}
	}
	for _, kw := range high {
		if strings.Contains(lower, kw) {
			return "high"
		}
	}
	for _, kw := range medium {
		if strings.Contains(lower, kw) {
			return "medium"
		}
	}
	return "info"
}

// buildBaseURL extracts scheme + host from any URL of the target.
func buildBaseURL(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}
