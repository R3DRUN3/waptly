package checks

import (
	"net/http"
	"regexp"
	"strings"
)

func init() {
	Register(&ServerBannerCheck{})
}

// bannerHeaders are the headers that commonly leak technology/version info.
var bannerHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Generator",
	"X-Drupal-Cache",
	"X-Wordpress-Cache",
	"Via",
	"X-Backend-Server",
	"X-Forwarded-Server",
	"X-Application-Context",
	"X-Runtime", // Rails
	"X-Served-By",
	"X-Shopify-Stage",
	"X-Powered-CMS",
}

// versionPattern matches version strings like 2.4.49, 1.0, 7.4.3-alpine etc.
var versionPattern = regexp.MustCompile(`\d+\.\d+[\.\d\w\-]*`)

// techSignatures maps a keyword (lowercased) to a normalized technology name.
// Used to enrich the finding with a clean tech label.
var techSignatures = map[string]string{
	// Web servers
	"apache":    "Apache HTTPD",
	"nginx":     "nginx",
	"iis":       "Microsoft IIS",
	"lighttpd":  "lighttpd",
	"caddy":     "Caddy",
	"gunicorn":  "Gunicorn",
	"openresty": "OpenResty",
	"litespeed": "LiteSpeed",

	// Languages / runtimes
	"php":     "PHP",
	"python":  "Python",
	"ruby":    "Ruby",
	"perl":    "Perl",
	"java":    "Java",
	"node":    "Node.js",
	"asp.net": "ASP.NET",
	"mono":    "Mono",

	// Frameworks
	"express":   "Express.js",
	"rails":     "Ruby on Rails",
	"django":    "Django",
	"laravel":   "Laravel",
	"symfony":   "Symfony",
	"spring":    "Spring",
	"wordpress": "WordPress",
	"drupal":    "Drupal",
	"joomla":    "Joomla",
	"magento":   "Magento",
	"shopify":   "Shopify",

	// CDN / infrastructure
	"cloudflare": "Cloudflare",
	"fastly":     "Fastly",
	"akamai":     "Akamai",
	"varnish":    "Varnish Cache",
	"squid":      "Squid Proxy",
}

// BannerFinding represents a single header that leaked information.
type BannerFinding struct {
	Header     string   `json:"header"`
	Value      string   `json:"value"`
	Technology string   `json:"technology,omitempty"`
	Versions   []string `json:"versions,omitempty"`
}

// ServerBannerCheck detects technology and version disclosure via HTTP headers.
type ServerBannerCheck struct{}

func (s *ServerBannerCheck) Name() string { return "server_banner" }

func (s *ServerBannerCheck) Run(_ string, resp *http.Response) Result {
	findings := []BannerFinding{}
	technologiesFound := []string{}
	versionsFound := []string{}

	for _, header := range bannerHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			continue
		}

		finding := BannerFinding{
			Header: header,
			Value:  value,
		}

		// Extract version strings.
		if versions := versionPattern.FindAllString(value, -1); len(versions) > 0 {
			finding.Versions = versions
			versionsFound = append(versionsFound, versions...)
		}

		// Match technology signatures.
		lower := strings.ToLower(value)
		for keyword, techName := range techSignatures {
			if strings.Contains(lower, keyword) {
				finding.Technology = techName
				technologiesFound = append(technologiesFound, techName)
				break
			}
		}

		findings = append(findings, finding)
	}

	// passed = no version or technology info was leaked.
	passed := len(findings) == 0

	return Result{
		CheckName: s.Name(),
		Passed:    passed,
		Details: map[string]any{
			"findings":     findings,
			"technologies": dedupe(technologiesFound),
			"versions":     dedupe(versionsFound),
			"leaking":      !passed,
		},
	}
}

// dedupe removes duplicate strings from a slice preserving order.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
