package checks

import (
	"net/http"
)

func init() {
	Register(&HeadersCheck{})
}

// securityHeaders maps header name -> description of what it protects against.
var securityHeaders = map[string]string{
	"Strict-Transport-Security": "Enforces HTTPS (HSTS)",
	"Content-Security-Policy":   "Mitigates XSS and data injection attacks",
	"X-Content-Type-Options":    "Prevents MIME-type sniffing",
	"X-Frame-Options":           "Protects against clickjacking",
	"Referrer-Policy":           "Controls referrer information leakage",
	"Permissions-Policy":        "Restricts browser feature access",
	"Cross-Origin-Opener-Policy": "Isolates browsing context against XS-Leaks",
	"Cross-Origin-Resource-Policy": "Controls cross-origin resource sharing",
}

// HeadersCheck verifies the presence of important HTTP security headers.
type HeadersCheck struct{}

func (h *HeadersCheck) Name() string { return "http_security_headers" }

func (h *HeadersCheck) Run(_ string, resp *http.Response) Result {
	present := map[string]string{}
	missing := map[string]string{}

	for header, description := range securityHeaders {
		if val := resp.Header.Get(header); val != "" {
			present[header] = val
		} else {
			missing[header] = description
		}
	}

	return Result{
		CheckName: h.Name(),
		Passed:    len(missing) == 0,
		Details: map[string]any{
			"present": present,
			"missing": missing,
		},
	}
}
