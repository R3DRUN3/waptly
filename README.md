# waptly  

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)  ![Red Team Badge](https://img.shields.io/badge/Team-Red-red)

A fast, extensible CLI tool to automate security posture checks during Web Application Penetration Testing (WAPT) activities.  
Waptly scans one or more targets concurrently and outputs a structured JSON report, helpin gpentesters map the webapp risk surface.  

---


> [!CAUTION]
> Waptly is intended for authorized security testing only.  
> Do not use against systems you do not own or have explicit permission to test.   





## Checks

Checks include (but are not limited to):  

| Module | Description |
|---|---|
| `http_security_headers` | Detects missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `waf_detection` | Fingerprints WAF presence via response headers (Cloudflare, Akamai, AWS, etc.) |
| `tls` | Checks TLS version, certificate expiry, self-signed certs and weak ciphers |
| `robots_txt` | Parses robots.txt and flags sensitive paths exposed to crawlers |
| `http_methods` | Probes dangerous HTTP methods (TRACE, PUT, DELETE, CONNECT) |

---

## Installation/usage

TO DO


## Output  
Waptly outputs a single JSON report to stdout, here is an example:  
```json
{
  "generated_at": "2026-04-20T07:27:30Z",
  "targets": [
    {
      "target": "https://pentest-ground.com:4280/",
      "checks": [
        {
          "check": "exposed_files",
          "passed": false,
          "details": {
            "base_url": "https://pentest-ground.com:4280",
            "found": [
              {
                "path": "/phpinfo.php",
                "status_code": 200,
                "content_type": "text/html; charset=UTF-8",
                "body_preview": "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\"><head>\n<style type=\"text/css\">\nbody {background-color: #fff; co...",
                "severity": "high"
              }
            ],
            "found_count": 1,
            "probed": 30
          }
        },
        {
          "check": "http_security_headers",
          "passed": false,
          "details": {
            "missing": {
              "Content-Security-Policy": "Mitigates XSS and data injection attacks",
              "Cross-Origin-Opener-Policy": "Isolates browsing context against XS-Leaks",
              "Cross-Origin-Resource-Policy": "Controls cross-origin resource sharing",
              "Permissions-Policy": "Restricts browser feature access",
              "Referrer-Policy": "Controls referrer information leakage",
              "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
              "X-Content-Type-Options": "Prevents MIME-type sniffing",
              "X-Frame-Options": "Protects against clickjacking"
            },
            "present": {}
          }
        },
        {
          "check": "http_methods",
          "passed": false,
          "details": {
            "dangerous_methods": [
              {
                "method": "TRACK",
                "status_code": 200,
                "risk": "Variant of TRACE, used by older IIS servers",
                "severity": "high",
                "advertised_by_options": false
              },
              {
                "method": "PUT",
                "status_code": 200,
                "risk": "Arbitrary file upload may be possible",
                "severity": "critical",
                "advertised_by_options": false
              },
              {
                "method": "DELETE",
                "status_code": 200,
                "risk": "Destructive operations may be possible",
                "severity": "critical",
                "advertised_by_options": false
              },
              {
                "method": "CONNECT",
                "status_code": 400,
                "risk": "Server may be usable as an HTTP proxy",
                "severity": "high",
                "advertised_by_options": false
              },
              {
                "method": "PATCH",
                "status_code": 200,
                "risk": "Partial resource modification may be possible",
                "severity": "medium",
                "advertised_by_options": false
              }
            ],
            "issues": [
              "TRACK enabled (HTTP 200) — Variant of TRACE, used by older IIS servers",
              "PUT enabled (HTTP 200) — Arbitrary file upload may be possible",
              "DELETE enabled (HTTP 200) — Destructive operations may be possible",
              "CONNECT enabled (HTTP 400) — Server may be usable as an HTTP proxy",
              "PATCH enabled (HTTP 200) — Partial resource modification may be possible"
            ],
            "options_advertised": null
          }
        },
        {
          "check": "robots_txt",
          "passed": true,
          "details": {
            "entries": [
              {
                "user_agent": "*",
                "disallowed": [
                  "/"
                ]
              }
            ],
            "found": true,
            "raw_lines": [
              "User-agent: *",
              "Disallow: /"
            ],
            "robots_url": "https://pentest-ground.com:4280/robots.txt",
            "sensitive_paths": null,
            "status_code": 200
          }
        },
        {
          "check": "server_banner",
          "passed": false,
          "details": {
            "findings": [
              {
                "header": "Server",
                "value": "nginx/1.29.8",
                "technology": "nginx",
                "versions": [
                  "1.29.8"
                ]
              },
              {
                "header": "X-Powered-By",
                "value": "PHP/8.5.5",
                "technology": "PHP",
                "versions": [
                  "8.5.5"
                ]
              }
            ],
            "leaking": true,
            "technologies": [
              "nginx",
              "PHP"
            ],
            "versions": [
              "1.29.8",
              "8.5.5"
            ]
          }
        },
        {
          "check": "tls",
          "passed": true,
          "details": {
            "certificates": [
              {
                "days_until_expiry": 63,
                "dns_names": [
                  "pentest-ground.com"
                ],
                "expired": false,
                "is_ca": false,
                "issuer": "E7",
                "not_after": "2026-06-23T03:10:40Z",
                "not_before": "2026-03-25T03:10:41Z",
                "self_signed": false,
                "signature_algorithm": "ECDSA-SHA384",
                "subject": "pentest-ground.com"
              },
              {
                "dns_names": null,
                "is_ca": true,
                "issuer": "ISRG Root X1",
                "not_after": "2027-03-12T23:59:59Z",
                "not_before": "2024-03-13T00:00:00Z",
                "signature_algorithm": "SHA256-RSA",
                "subject": "E7"
              }
            ],
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "issues": [],
            "tls_version": "TLS 1.3",
            "weak_cipher": false
          }
        },
        {
          "check": "waf_detection",
          "passed": false,
          "details": {
            "detected": [],
            "evidence": {},
            "waf_detected": false
          }
        }
      ]
    }
  ]
}
```  

## Adding a new check  
1. Create `checks/your_check.go` in the `checks/` package
2. Implement the Check interface
3. Register it via `init()` (no changes to `main.go` needed)
