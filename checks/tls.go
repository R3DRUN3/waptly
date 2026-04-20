package checks

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func init() {
	Register(&TLSCheck{})
}

// tlsVersionNames maps tls package constants to human-readable strings.
var tlsVersionNames = map[uint16]string{
	tls.VersionSSL30: "SSLv3",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// insecureVersions are versions that should be flagged as failures.
var insecureVersions = map[uint16]bool{
	tls.VersionSSL30: true,
	tls.VersionTLS10: true,
	tls.VersionTLS11: true,
}

// weakSignatureAlgorithms flags cert signature algorithms considered weak.
var weakSignatureAlgorithms = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA:    "MD2WithRSA",
	x509.MD5WithRSA:    "MD5WithRSA",
	x509.SHA1WithRSA:   "SHA1WithRSA",
	x509.ECDSAWithSHA1: "ECDSAWithSHA1",
}

// certExpiryWarnDays is how many days before expiry we start warning.
const certExpiryWarnDays = 30

// TLSCheck inspects the TLS connection and certificate of a target.
type TLSCheck struct{}

func (t *TLSCheck) Name() string { return "tls" }

func (t *TLSCheck) Run(target string, resp *http.Response) Result {
	// Non-HTTPS targets: skip gracefully.
	if resp.TLS == nil {
		return Result{
			CheckName: t.Name(),
			Passed:    false,
			Details: map[string]any{
				"error": "target is not using HTTPS",
			},
		}
	}

	tlsState := resp.TLS
	issues := []string{}

	// --- TLS Version ---
	versionName, ok := tlsVersionNames[tlsState.Version]
	if !ok {
		versionName = fmt.Sprintf("unknown (0x%04x)", tlsState.Version)
	}
	if insecureVersions[tlsState.Version] {
		issues = append(issues, fmt.Sprintf("insecure TLS version in use: %s", versionName))
	}

	// --- Certificate chain ---
	certDetails := []map[string]any{}
	now := time.Now()

	for i, cert := range tlsState.PeerCertificates {
		cd := map[string]any{
			"subject":    cert.Subject.CommonName,
			"issuer":     cert.Issuer.CommonName,
			"not_before": cert.NotBefore.Format(time.RFC3339),
			"not_after":  cert.NotAfter.Format(time.RFC3339),
			"is_ca":      cert.IsCA,
			"dns_names":  cert.DNSNames,
		}

		// Expiry checks (leaf cert only — index 0)
		if i == 0 {
			if now.After(cert.NotAfter) {
				issues = append(issues, "certificate has EXPIRED")
				cd["expired"] = true
			} else {
				cd["expired"] = false
				daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
				cd["days_until_expiry"] = daysLeft
				if daysLeft <= certExpiryWarnDays {
					issues = append(issues,
						fmt.Sprintf("certificate expires in %d days", daysLeft))
				}
			}

			// Self-signed: subject == issuer
			if cert.Subject.String() == cert.Issuer.String() {
				issues = append(issues, "certificate is self-signed")
				cd["self_signed"] = true
			} else {
				cd["self_signed"] = false
			}
		}

		// Weak signature algorithm
		if weakName, isWeak := weakSignatureAlgorithms[cert.SignatureAlgorithm]; isWeak {
			issues = append(issues,
				fmt.Sprintf("certificate uses weak signature algorithm: %s", weakName))
			cd["weak_signature"] = weakName
		} else {
			cd["signature_algorithm"] = cert.SignatureAlgorithm.String()
		}

		certDetails = append(certDetails, cd)
	}

	// --- Cipher suite ---
	cipherName := tls.CipherSuiteName(tlsState.CipherSuite)
	weakCipher := isWeakCipher(cipherName)
	if weakCipher {
		issues = append(issues, fmt.Sprintf("weak cipher suite in use: %s", cipherName))
	}

	passed := len(issues) == 0

	return Result{
		CheckName: t.Name(),
		Passed:    passed,
		Details: map[string]any{
			"tls_version":  versionName,
			"cipher_suite": cipherName,
			"weak_cipher":  weakCipher,
			"certificates": certDetails,
			"issues":       issues,
		},
	}
}

// isWeakCipher returns true for cipher suites considered insecure.
// Go's tls package already refuses most broken ciphers, but we flag
// the known-weak ones that may still be negotiated.
func isWeakCipher(name string) bool {
	weakKeywords := []string{
		"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
	}
	upper := strings.ToUpper(name)
	for _, kw := range weakKeywords {
		if strings.Contains(upper, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}
