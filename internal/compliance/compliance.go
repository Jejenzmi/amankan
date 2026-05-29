// Package compliance maps a technical finding (by CWE) to governance controls:
// Vulnerability -> CWE -> OWASP -> ISO 27001 / BSSN / COBIT. This is the
// "Compliance Policy Engine" of the design, seeded for the Phase 1 PoC.
package compliance

import "github.com/amankan/amankan/internal/models"

// entry holds the control mappings and remediation guidance for one CWE.
type entry struct {
	owaspTop10 string // OWASP Top 10 2021 category
	owaspASVS  string // ASVS verification requirement
	iso27001   string // ISO/IEC 27001:2022 Annex A control
	bssn       string // BSSN / SNI ISO 27001 / Indeks KAMI reference
	cobit      string // COBIT 2019 management objective
	remedy     models.RemediationGuide
}

// catalog is the seed mapping table. In production this would live in Neo4j /
// PostgreSQL and be editable; here it is an in-code source of truth.
var catalog = map[string]entry{
	"CWE-327": { // Use of a broken or risky cryptographic algorithm
		owaspTop10: "A02:2021 Cryptographic Failures",
		owaspASVS:  "ASVS V6.2.1 Algorithms",
		iso27001:   "A.8.24 Use of cryptography",
		bssn:       "Indeks KAMI - Pengamanan; Std. Kriptografi Nasional",
		cobit:      "DSS05 Manage Security Services",
		remedy: models.RemediationGuide{
			Summary: "Replace weak/legacy cryptographic algorithms with approved ones.",
			Steps: []string{
				"Disable TLS < 1.2; prefer TLS 1.3.",
				"Use RSA >= 2048-bit or ECDSA P-256; rotate weak keys.",
				"Remove deprecated ciphers (RC4, 3DES, MD5, SHA-1).",
			},
			Refs: []string{"NIST SP 800-52r2", "BSSN Standar Kriptografi Nasional"},
		},
	},
	"CWE-502": { // Deserialization of untrusted data (e.g. Log4Shell)
		owaspTop10: "A08:2021 Software and Data Integrity Failures",
		owaspASVS:  "ASVS V5.5 Deserialization Prevention",
		iso27001:   "A.8.28 Secure coding",
		bssn:       "Indeks KAMI - Pengelolaan Insiden",
		cobit:      "BAI03 Manage Solutions Identification and Build",
		remedy: models.RemediationGuide{
			Summary: "Patch the vulnerable component and block untrusted deserialization.",
			Steps: []string{
				"Upgrade affected library to a fixed version immediately.",
				"Apply vendor mitigations / disable dangerous lookups.",
				"Add WAF rules as a temporary compensating control.",
			},
			Refs: []string{"CVE-2021-44228", "OWASP Deserialization Cheat Sheet"},
		},
	},
	"CWE-538": { // Insertion of sensitive information into externally-accessible file
		owaspTop10: "A01:2021 Broken Access Control",
		owaspASVS:  "ASVS V8.1 General Data Protection",
		iso27001:   "A.5.34 Privacy and protection of PII; A.8.3 Information access restriction",
		bssn:       "Indeks KAMI - Pengamanan Aset Informasi",
		cobit:      "DSS06 Manage Business Process Controls",
		remedy: models.RemediationGuide{
			Summary: "Remove externally-exposed sensitive files and restrict access.",
			Steps: []string{
				"Block access to VCS/metadata paths (e.g. /.git, /.env).",
				"Rotate any secrets that were exposed.",
				"Add deny rules at the web server / reverse proxy.",
			},
		},
	},
	"CWE-693": { // Protection mechanism failure (missing security headers)
		owaspTop10: "A05:2021 Security Misconfiguration",
		owaspASVS:  "ASVS V14.4 HTTP Security Headers",
		iso27001:   "A.8.9 Configuration management",
		bssn:       "Indeks KAMI - Pengelolaan Konfigurasi",
		cobit:      "BAI10 Manage Configuration",
		remedy: models.RemediationGuide{
			Summary: "Add the missing security response headers.",
			Steps: []string{
				"Set Content-Security-Policy, X-Content-Type-Options, X-Frame-Options.",
				"Add Strict-Transport-Security on HTTPS endpoints.",
			},
		},
	},
	"CWE-269": { // Improper privilege management (local privilege escalation)
		owaspTop10: "A01:2021 Broken Access Control",
		owaspASVS:  "ASVS V1.2 Authentication Architecture",
		iso27001:   "A.8.2 Privileged access rights; A.8.18 Use of privileged utility programs",
		bssn:       "Indeks KAMI - Pengelolaan Hak Akses",
		cobit:      "DSS05 Manage Security Services",
		remedy: models.RemediationGuide{
			Summary: "Patch the privilege-escalation vector and tighten privilege boundaries.",
			Steps: []string{
				"Apply the vendor patch for the affected component (e.g. pkexec/polkit).",
				"Enforce least privilege; remove unnecessary SUID/SGID binaries.",
				"Audit local accounts and sudo rules.",
			},
			Refs: []string{"CVE-2021-4034 (PwnKit)", "OWASP Access Control Cheat Sheet"},
		},
	},
	"CWE-250": { // Execution with unnecessary privileges
		owaspTop10: "A04:2021 Insecure Design",
		owaspASVS:  "ASVS V1.2 Authentication Architecture",
		iso27001:   "A.8.2 Privileged access rights",
		bssn:       "Indeks KAMI - Pengelolaan Hak Akses",
		cobit:      "DSS05 Manage Security Services",
		remedy: models.RemediationGuide{
			Summary: "Drop unnecessary privileges and run services as least-privileged users.",
			Steps: []string{
				"Run services under dedicated low-privilege accounts.",
				"Remove overly-permissive sudo/Administrator grants.",
			},
		},
	},
	// Open-port / service exposure findings from nmap are categorized as misconfig.
	"CWE-1327": { // Binding to an unrestricted IP address (exposed service)
		owaspTop10: "A05:2021 Security Misconfiguration",
		owaspASVS:  "ASVS V1.14 Configuration Architecture",
		iso27001:   "A.8.20 Networks security; A.8.22 Segregation of networks",
		bssn:       "Indeks KAMI - Pengamanan Jaringan",
		cobit:      "DSS05 Manage Security Services",
		remedy: models.RemediationGuide{
			Summary: "Restrict exposed network services to required networks only.",
			Steps: []string{
				"Close or firewall ports that need not be public.",
				"Bind administrative services (SSH, DB) to private interfaces.",
				"Enforce network segmentation / security groups.",
			},
		},
	},
}

// defaultEntry is used when a CWE is not in the catalog so every finding still
// carries at least a baseline mapping.
var defaultEntry = entry{
	owaspTop10: "A06:2021 Vulnerable and Outdated Components",
	owaspASVS:  "ASVS V1.1 Secure Software Development Lifecycle",
	iso27001:   "A.8.8 Management of technical vulnerabilities",
	bssn:       "Indeks KAMI - Manajemen Kerentanan",
	cobit:      "APO12 Manage Risk",
	remedy: models.RemediationGuide{
		Summary: "Triage, validate, and remediate the identified weakness.",
		Steps:   []string{"Validate the finding to rule out false positives.", "Apply vendor patch or configuration hardening."},
	},
}

// Refs returns the compliance references for a CWE.
func Refs(cwe string) []models.ComplianceRef {
	e, ok := catalog[cwe]
	if !ok {
		e = defaultEntry
	}
	return []models.ComplianceRef{
		{Framework: "OWASP-Top10", Control: e.owaspTop10, Title: "OWASP Top 10 2021"},
		{Framework: "OWASP-ASVS", Control: e.owaspASVS, Title: "OWASP ASVS"},
		{Framework: "ISO27001", Control: e.iso27001, Title: "ISO/IEC 27001:2022 Annex A"},
		{Framework: "BSSN", Control: e.bssn, Title: "BSSN / Indeks KAMI"},
		{Framework: "COBIT2019", Control: e.cobit, Title: "COBIT 2019"},
	}
}

// Remediation returns remediation guidance for a CWE.
func Remediation(cwe string) models.RemediationGuide {
	if e, ok := catalog[cwe]; ok {
		return e.remedy
	}
	return defaultEntry.remedy
}

// privEscCWEs are weaknesses whose presence on a host implies a local
// privilege-escalation capability (used to auto-derive CAN_ESCALATE edges).
var privEscCWEs = map[string]bool{
	"CWE-269": true, // Improper Privilege Management
	"CWE-250": true, // Execution with Unnecessary Privileges
	"CWE-264": true, // Permissions, Privileges, and Access Controls
	"CWE-276": true, // Incorrect Default Permissions
	"CWE-732": true, // Incorrect Permission Assignment for Critical Resource
	"CWE-862": true, // Missing Authorization
	"CWE-863": true, // Incorrect Authorization
}

// IsPrivEsc reports whether a CWE indicates a local privilege-escalation vector.
func IsPrivEsc(cwe string) bool { return privEscCWEs[cwe] }

// CatalogCWEs lists the CWEs that have explicit mappings (for the /compliance API).
func CatalogCWEs() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	return out
}
