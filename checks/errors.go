package checks

import (
	"bytes"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(&ErrorHandlingCheck{})
}

type ErrorTriggerFinding struct {
	PayloadType string `json:"payload_type"`
	Path        string `json:"path"`
	Triggered   bool   `json:"triggered_500"`
	StackTrace  string `json:"stack_trace,omitempty"`
}

type ErrorHandlingCheck struct{}

func (c *ErrorHandlingCheck) Name() string { return "error_handling" }

func (c *ErrorHandlingCheck) Run(target string, _ *http.Response) Result {
	var findings []ErrorTriggerFinding
	client := &http.Client{Timeout: 8 * time.Second}

	breakPayloads := []struct {
		desc string
		path string
		body string
		ct   string
	}{
		{"large_payload", "/", strings.Repeat("A", 3*1024*1024), "application/octet-stream"},
		{"malformed_json", "/", "{this: is: not: json", "application/json"},
		{"unicode_fuzz", "/", "\xff\xfe\xfa\xfb", "text/plain"},
		{"sql_injection", "/?id=' OR 1=1--", "", ""},
		{"cmd_injection", "/?q=;cat /etc/passwd", "", ""},
	}

	for _, bp := range breakPayloads {
		url := target
		if bp.path != "/" {
			url = strings.TrimRight(target, "/") + bp.path
		}

		var req *http.Request
		var err error

		if bp.body != "" {
			req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(bp.body)))
		} else {
			req, err = http.NewRequest("GET", url, nil)
		}
		if err != nil {
			continue
		}

		if bp.ct != "" {
			req.Header.Set("Content-Type", bp.ct)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		finding := ErrorTriggerFinding{
			PayloadType: bp.desc,
			Path:        bp.path,
		}

		if resp.StatusCode == http.StatusInternalServerError {
			finding.Triggered = true
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			finding.StackTrace = extractErrorEvidence(body)
		}

		resp.Body.Close()
		findings = append(findings, finding)
	}

	return Result{
		CheckName: c.Name(),
		Passed:    !hasTriggered500(findings),
		Details: map[string]any{
			"results": findings,
		},
	}
}

func hasTriggered500(findings []ErrorTriggerFinding) bool {
	for _, f := range findings {
		if f.Triggered {
			return true
		}
	}
	return false
}

func extractErrorEvidence(body []byte) string {
	s := string(body)

	titleRx := regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	if m := titleRx.FindStringSubmatch(s); len(m) > 1 {
		return strings.TrimSpace(html.UnescapeString(stripTags(m[1])))
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)Traceback \(most recent call last\):`),
		regexp.MustCompile(`(?i)Exception in thread|java\.lang\.\w+Exception|at [\w\./$<>:-]+\([^\)]+:\d+\)`),
		regexp.MustCompile(`(?i)System\.StackTrace`),
		regexp.MustCompile(`(?m)^\s*at\s+[^\n<]+`),
		regexp.MustCompile(`(?i)SyntaxError:[^\n<]+`),
		regexp.MustCompile(`(?i)goroutine \d+ \[.+\]:`),
		regexp.MustCompile(`(?i)PHP (Fatal|Parse|Warning|Notice) error[^\n<]*`),
	}

	for _, rx := range patterns {
		if m := rx.Find(body); m != nil {
			return strings.TrimSpace(html.UnescapeString(string(m)))
		}
	}

	clean := strings.TrimSpace(html.UnescapeString(stripTags(s)))
	if len(clean) > 200 {
		clean = clean[:200]
	}
	return clean
}

func stripTags(s string) string {
	tagRx := regexp.MustCompile(`(?s)<[^>]*>`)
	return tagRx.ReplaceAllString(s, " ")
}
