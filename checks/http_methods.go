package checks

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func init() {
	Register(&HTTPMethodsCheck{})
}

// methodChecks defines each method to probe and its associated risk.
var methodChecks = []struct {
	Method   string
	Risk     string
	Severity string
}{
	{Method: "TRACE", Risk: "Cross-Site Tracing (XST) — can leak auth headers/cookies", Severity: "high"},
	{Method: "TRACK", Risk: "Variant of TRACE, used by older IIS servers", Severity: "high"},
	{Method: "PUT", Risk: "Arbitrary file upload may be possible", Severity: "critical"},
	{Method: "DELETE", Risk: "Destructive operations may be possible", Severity: "critical"},
	{Method: "CONNECT", Risk: "Server may be usable as an HTTP proxy", Severity: "high"},
	{Method: "PATCH", Risk: "Partial resource modification may be possible", Severity: "medium"},
}

// HTTPMethodsCheck probes dangerous HTTP methods on the target.
type HTTPMethodsCheck struct{}

func (h *HTTPMethodsCheck) Name() string { return "http_methods" }

func (h *HTTPMethodsCheck) Run(target string, resp *http.Response) Result {
	client := &http.Client{
		Timeout: 8 * time.Second,
		// Do NOT follow redirects — a 301/302 on a dangerous method
		// is still meaningful and we want the raw response code.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// First, fetch allowed methods via OPTIONS.
	advertised := probeOptions(client, target)

	// Then actively probe each dangerous method individually.
	type MethodResult struct {
		Method     string `json:"method"`
		StatusCode int    `json:"status_code"`
		Risk       string `json:"risk"`
		Severity   string `json:"severity"`
		Advertised bool   `json:"advertised_by_options"`
	}

	dangerous := []MethodResult{}
	issues := []string{}

	for _, mc := range methodChecks {
		code, err := probeMethod(client, target, mc.Method)
		if err != nil {
			continue
		}

		// A method is considered "enabled" if the server responds with
		// anything other than 405 (Not Allowed) or 501 (Not Implemented).
		// 200, 201, 204, 301, 302, 400, 403 all indicate the method is
		// understood and (at least partially) processed by the server.
		if !isMethodDisabled(code) {
			dangerous = append(dangerous, MethodResult{
				Method:     mc.Method,
				StatusCode: code,
				Risk:       mc.Risk,
				Severity:   mc.Severity,
				Advertised: contains(advertised, mc.Method),
			})
			issues = append(issues, fmt.Sprintf("%s enabled (HTTP %d) — %s", mc.Method, code, mc.Risk))
		}
	}

	passed := len(dangerous) == 0

	return Result{
		CheckName: h.Name(),
		Passed:    passed,
		Details: map[string]any{
			"options_advertised": advertised,
			"dangerous_methods":  dangerous,
			"issues":             issues,
		},
	}
}

// probeOptions sends an OPTIONS request and parses the Allow header.
func probeOptions(client *http.Client, target string) []string {
	req, err := http.NewRequest(http.MethodOptions, target, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if allow == "" {
		allow = resp.Header.Get("Public") // older IIS fallback
	}
	if allow == "" {
		return nil
	}

	var methods []string
	for _, m := range strings.Split(allow, ",") {
		m = strings.TrimSpace(strings.ToUpper(m))
		if m != "" {
			methods = append(methods, m)
		}
	}
	return methods
}

// probeMethod sends a single HTTP request with the given method and returns the status code.
func probeMethod(client *http.Client, target, method string) (int, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return 0, fmt.Errorf("could not build request: %w", err)
	}

	// For TRACE we also send a custom header to verify server reflection.
	if method == "TRACE" {
		req.Header.Set("X-Wapt-Trace", "test-xst-probe")
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// isMethodDisabled returns true when the status code clearly means
// the server does not support the method.
func isMethodDisabled(code int) bool {
	return code == http.StatusMethodNotAllowed || // 405
		code == http.StatusNotImplemented // 501
}

// contains is a simple case-insensitive string slice lookup.
func contains(slice []string, val string) bool {
	val = strings.ToUpper(val)
	for _, s := range slice {
		if strings.ToUpper(s) == val {
			return true
		}
	}
	return false
}
