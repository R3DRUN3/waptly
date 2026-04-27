package checks

import (
	"net/http"
	"net/url"
	"strings"
	"time"
	"fmt"
)

type HTTPSRedirectCheck struct{}

func init() {
	Register(&HTTPSRedirectCheck{})
}

func (h *HTTPSRedirectCheck) Name() string { return "https_redirect" }

func (h *HTTPSRedirectCheck) Run(target string, _ *http.Response) Result {
	result := Result{
		CheckName: h.Name(),
		Passed:    false,
		Details:   map[string]any{},
	}

	// 1. Normalize target as URL
	parsed, err := parseAsURL(target)
	if err != nil {
		result.Error = "Unable to parse target: " + err.Error()
		return result
	}

	// 2. Make http:// variant for the request
	httpURL := parsed
	httpURL.Scheme = "http"
	if httpURL.Port() == "443" {
		httpURL.Host = strings.TrimSuffix(httpURL.Host, ":443") + ":80"
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(httpURL.String())
	if err != nil {
		result.Error = fmt.Sprintf("HTTP request error: %v", err)
		return result
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")

	// Determine canonical HTTPS url for this target
	httpsURL := parsed
	httpsURL.Scheme = "https"

	// Accept 301, 302, 307, 308 (most common for HTTPS redirects)
	isHTTPSRedirect := (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308) &&
		(strings.HasPrefix(loc, httpsURL.String()) || strings.HasPrefix(loc, "https://"))

	result.Passed = isHTTPSRedirect
	result.Details["http_status"] = resp.StatusCode
	result.Details["location"] = loc
	if isHTTPSRedirect {
		result.Details["message"] = "Redirects to HTTPS endpoint."
	} else {
		result.Details["message"] = "No valid HTTP to HTTPS redirect."
	}
	return result
}

// parseAsURL normalizes any target input to a *url.URL
func parseAsURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		// assume https as canonical for webapps
		raw = "https://" + raw
	}
	return url.Parse(raw)
}
