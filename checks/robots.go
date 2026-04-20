package checks

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func init() {
	Register(&RobotsCheck{})
}

// sensitiveKeywords are path patterns that hint at interesting/sensitive endpoints.
var sensitiveKeywords = []string{
	"admin", "backup", "config", "database", "db", "debug",
	"dev", "dump", "env", "git", "hidden", "install", "internal",
	"log", "logs", "manage", "passwd", "private", "secret",
	"setup", "shell", "staging", "swagger", "test", "tmp",
	"upload", "uploads", "vault", "wp-admin", "wp-login",
}

// RobotsCheck fetches and parses robots.txt, flagging sensitive disallowed paths.
type RobotsCheck struct{}

func (r *RobotsCheck) Name() string { return "robots_txt" }

func (r *RobotsCheck) Run(target string, resp *http.Response) Result {
	robotsURL, err := buildRobotsURL(target)
	if err != nil {
		return Result{
			CheckName: r.Name(),
			Passed:    true,
			Details: map[string]any{
				"error": fmt.Sprintf("could not build robots.txt URL: %v", err),
			},
		}
	}

	// Fetch robots.txt with a fresh request (independent of the main scan resp).
	robotsResp, err := http.Get(robotsURL) //nolint:gosec
	if err != nil {
		return Result{
			CheckName: r.Name(),
			Passed:    true,
			Details: map[string]any{
				"robots_url": robotsURL,
				"found":      false,
				"error":      fmt.Sprintf("request failed: %v", err),
			},
		}
	}
	defer robotsResp.Body.Close()

	// 404 or other non-200: no robots.txt present.
	if robotsResp.StatusCode != http.StatusOK {
		return Result{
			CheckName: r.Name(),
			Passed:    true,
			Details: map[string]any{
				"robots_url":  robotsURL,
				"found":       false,
				"status_code": robotsResp.StatusCode,
			},
		}
	}

	entries, rawLines := parseRobots(robotsResp.Body)

	sensitivePaths := flagSensitivePaths(entries)
	passed := len(sensitivePaths) == 0

	return Result{
		CheckName: r.Name(),
		Passed:    passed,
		Details: map[string]any{
			"robots_url":      robotsURL,
			"found":           true,
			"status_code":     robotsResp.StatusCode,
			"entries":         entries,
			"raw_lines":       rawLines,
			"sensitive_paths": sensitivePaths,
		},
	}
}

// RobotsEntry represents a single User-agent block with its directives.
type RobotsEntry struct {
	UserAgent  string   `json:"user_agent"`
	Disallowed []string `json:"disallowed,omitempty"`
	Allowed    []string `json:"allowed,omitempty"`
	Sitemaps   []string `json:"sitemaps,omitempty"`
}

// SensitivePath holds a flagged path and the keyword that matched.
type SensitivePath struct {
	Path    string `json:"path"`
	Keyword string `json:"keyword"`
	Rule    string `json:"rule"` // "disallow" or "allow"
}

// parseRobots reads a robots.txt body and returns structured entries + raw lines.
func parseRobots(body io.Reader) ([]RobotsEntry, []string) {
	var entries []RobotsEntry
	var rawLines []string

	var current *RobotsEntry

	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rawLines = append(rawLines, line)

		// Skip empty lines and comments — but flush current block on blank line.
		if line == "" {
			if current != nil {
				entries = append(entries, *current)
				current = nil
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		// Strip inline comments (e.g. "Disallow: /admin # sensitive")
		if idx := strings.Index(value, "#"); idx != -1 {
			value = strings.TrimSpace(value[:idx])
		}

		switch directive {
		case "user-agent":
			// Start a new block if we hit a fresh User-agent.
			if current == nil {
				current = &RobotsEntry{UserAgent: value}
			} else {
				// Multiple User-agent lines before first rule = same block.
				current.UserAgent = value
			}
		case "disallow":
			if current == nil {
				current = &RobotsEntry{UserAgent: "*"}
			}
			if value != "" {
				current.Disallowed = append(current.Disallowed, value)
			}
		case "allow":
			if current == nil {
				current = &RobotsEntry{UserAgent: "*"}
			}
			if value != "" {
				current.Allowed = append(current.Allowed, value)
			}
		case "sitemap":
			if current == nil {
				current = &RobotsEntry{UserAgent: "*"}
			}
			current.Sitemaps = append(current.Sitemaps, value)
		}
	}

	// Flush last block if file doesn't end with a blank line.
	if current != nil {
		entries = append(entries, *current)
	}

	return entries, rawLines
}

// flagSensitivePaths scans all entries for paths matching sensitiveKeywords.
func flagSensitivePaths(entries []RobotsEntry) []SensitivePath {
	var flagged []SensitivePath
	seen := map[string]bool{}

	check := func(path, rule string) {
		key := rule + ":" + path
		if seen[key] {
			return
		}
		lower := strings.ToLower(path)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lower, kw) {
				seen[key] = true
				flagged = append(flagged, SensitivePath{
					Path:    path,
					Keyword: kw,
					Rule:    rule,
				})
				break // one match per path is enough
			}
		}
	}

	for _, entry := range entries {
		for _, p := range entry.Disallowed {
			check(p, "disallow")
		}
		for _, p := range entry.Allowed {
			check(p, "allow")
		}
	}

	return flagged
}

// buildRobotsURL constructs the robots.txt URL from any page URL of the target.
func buildRobotsURL(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s/robots.txt", u.Scheme, u.Host), nil
}
