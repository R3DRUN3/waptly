package checks

import (
	"net/http"
	"strings"
)

func init() {
	Register(&WAFCheck{})
}

// wafSignatures maps WAF product name -> detection rules.
// Each rule is a header name and a value substring to look for.
type wafRule struct {
	Header    string
	Contains  string
}

var wafSignatures = map[string][]wafRule{
	"Cloudflare": {
		{Header: "Server", Contains: "cloudflare"},
		{Header: "CF-RAY", Contains: ""},
		{Header: "CF-Cache-Status", Contains: ""},
	},
	"AWS WAF / CloudFront": {
		{Header: "X-Amz-Cf-Id", Contains: ""},
		{Header: "X-Cache", Contains: "CloudFront"},
	},
	"Akamai": {
		{Header: "X-Check-Cacheable", Contains: ""},
		{Header: "X-Akamai-Transformed", Contains: ""},
		{Header: "Server", Contains: "AkamaiGHost"},
	},
	"Imperva / Incapsula": {
		{Header: "X-Iinfo", Contains: ""},
		{Header: "X-CDN", Contains: "Incapsula"},
	},
	"Sucuri": {
		{Header: "X-Sucuri-ID", Contains: ""},
		{Header: "Server", Contains: "Sucuri"},
	},
	"Fastly": {
		{Header: "X-Served-By", Contains: "cache-"},
		{Header: "Fastly-Debug-Digest", Contains: ""},
	},
	"F5 BIG-IP ASM": {
		{Header: "X-Cnection", Contains: ""},
		{Header: "Server", Contains: "BigIP"},
	},
	"ModSecurity": {
		{Header: "Server", Contains: "mod_security"},
		{Header: "X-Mod-Security", Contains: ""},
	},
}

// WAFCheck attempts to detect a Web Application Firewall from response headers.
type WAFCheck struct{}

func (w *WAFCheck) Name() string { return "waf_detection" }

func (w *WAFCheck) Run(_ string, resp *http.Response) Result {
	detected := []string{}
	evidence := map[string]string{}

	for wafName, rules := range wafSignatures {
		for _, rule := range rules {
			val := resp.Header.Get(rule.Header)
			if val == "" {
				continue
			}
			// Empty Contains means header presence alone is enough.
			if rule.Contains == "" || strings.Contains(strings.ToLower(val), strings.ToLower(rule.Contains)) {
				detected = append(detected, wafName)
				evidence[rule.Header] = val
				break // one match per WAF is enough
			}
		}
	}

	details := map[string]any{
		"waf_detected": len(detected) > 0,
		"detected":     detected,
		"evidence":     evidence,
	}

	return Result{
		CheckName: w.Name(),
		Passed:    len(detected) > 0, // "passed" = WAF is present (good posture)
		Details:   details,
	}
}
