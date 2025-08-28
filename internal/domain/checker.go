package domain

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"domain-scanner/internal/types"
	"github.com/likexian/whois"
)

var (
	// Pre-initialized maps for O(1) lookup
	availableIndicatorsMap   map[string]bool
	unavailableIndicatorsMap map[string]bool
	indicatorsOnce           sync.Once

	// Global config reference
	globalConfig *types.Config

	// WHOIS indicators for domain status detection
	registeredIndicators = []string{
		"registrar:",
		"registrant:",
		"creation date:",
		"created:",
		"updated date:",
		"updated:",
		"expiration date:",
		"expires:",
		"name server:",
		"nserver:",
		"nameserver:",
		"status: active",
		"status: client",
		"status: ok",
		"status: locked",
		"status: connect",  // Connect status indicates registered domain
		"status:connect",   // Version without space
		"domain name:",
		"domain:",
		"nsentry:",         // DENIC specific field
		"changed:",         // DENIC specific field
	}

	reservedIndicators = []string{
		"status: reserved",
		"status: restricted",
		"status: blocked",
		"status: prohibited",
		"status: reserved for registry",
		"status: reserved for registrar",
		"status: reserved for registry operator",
		"status: reserved for future use",
		"status: not available for registration",
		"status: not available for general registration",
		"status: reserved for special purposes",
		"status: reserved for government use",
		"status: reserved for educational institutions",
		"status: reserved for non-profit organizations",
		"domain reserved",
		"this domain is reserved",
		"reserved domain",
	}

	// WHOIS indicators for domain availability detection
	availableIndicators = []string{
		"no match for", "not found", "no data found", "no entries found",
		"domain not found", "no object found", "no matching record",
		"status: free", "status: available", "available for registration",
		"this domain is available", "domain is available", "domain available",
	}

	unavailableIndicators = []string{
		"registrar:", "registrant:", "creation date:", "updated date:",
		"expiration date:", "name server:", "nserver:", "status: registered",
		"status: active", "status: ok", "status: connect", "status:connect",
		"domain name:", "domain:", "nsentry:", "changed:",
	}
)

// SetConfig sets the global configuration for the domain checker
func SetConfig(config *types.Config) {
	globalConfig = config
}

// initIndicatorMaps initializes the indicator maps for fast lookup
func initIndicatorMaps() {
	indicatorsOnce.Do(func() {
		// Initialize available indicators map
		availableIndicatorsMap = make(map[string]bool, len(availableIndicators))
		for _, indicator := range availableIndicators {
			availableIndicatorsMap[indicator] = true
		}

		// Initialize unavailable indicators map
		unavailableIndicatorsMap = make(map[string]bool, len(unavailableIndicators))
		for _, indicator := range unavailableIndicators {
			unavailableIndicatorsMap[indicator] = true
		}
	})
}

// CheckDomainSignatures checks various signatures to determine domain status
func CheckDomainSignatures(domain string) ([]string, error) {
	var signatures []string

	// 1. Check DNS records (if enabled)
	if globalConfig == nil || globalConfig.Scanner.Methods.DNSCheck {
		dnsSignatures, err := checkDNSRecords(domain)
		if err == nil {
			signatures = append(signatures, dnsSignatures...)
		}
	}

	// 2. Check WHOIS information with retry (if enabled)
	if globalConfig == nil || globalConfig.Scanner.Methods.WHOISCheck {
		var whoisResult string
		maxRetries := 3  // Reduced retry count for speed
		for i := 0; i < maxRetries; i++ {
			result, err := whois.Whois(domain)
			if err == nil {
				whoisResult = result
				break
			}
			if i < maxRetries-1 {
				// Reduced retry interval for speed
				waitTime := time.Duration(1+i) * time.Second
				time.Sleep(waitTime)
			}
		}

		if whoisResult != "" {
			// Convert WHOIS response to lowercase for case-insensitive matching
			result := strings.ToLower(whoisResult)

			// First check for available indicators (these take precedence)
			isAvailable := false
			for _, indicator := range availableIndicators {
				if strings.Contains(result, indicator) {
					isAvailable = true
					break
				}
			}

			// Only check for registration if not explicitly available
			if !isAvailable {
				// Enhanced registration status detection
				for _, indicator := range registeredIndicators {
					if strings.Contains(result, indicator) {
						signatures = append(signatures, "WHOIS")
						break
					}
				}

				// Check for reserved domain indicators
				for _, indicator := range reservedIndicators {
					if strings.Contains(result, indicator) {
						signatures = append(signatures, "RESERVED")
						break
					}
				}
			}
		}
	}

	// 3. Check SSL certificate with timeout (if enabled)
	if globalConfig == nil || globalConfig.Scanner.Methods.SSLCheck {
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 5 * time.Second,
		}, "tcp", domain+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			defer func() {
				_ = conn.Close()
			}()
			state := conn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				signatures = append(signatures, "SSL")
			}
		}
	}

	return signatures, nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// checkDNSRecords checks various DNS records for the domain
func checkDNSRecords(domain string) ([]string, error) {
	var signatures []string

	// 1. Check DNS NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil && len(nsRecords) > 0 {
		signatures = append(signatures, "DNS_NS")
	}

	// 2. Check DNS A records
	ipRecords, err := net.LookupIP(domain)
	if err == nil && len(ipRecords) > 0 {
		signatures = append(signatures, "DNS_A")
	}

	// 3. Check DNS MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil && len(mxRecords) > 0 {
		signatures = append(signatures, "DNS_MX")
	}

	// 4. Check DNS TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil && len(txtRecords) > 0 {
		signatures = append(signatures, "DNS_TXT")
	}

	// 5. Check DNS CNAME records
	cnameRecord, err := net.LookupCNAME(domain)
	if err == nil && cnameRecord != "" && cnameRecord != domain+"." {
		signatures = append(signatures, "DNS_CNAME")
	}

	return signatures, nil
}

// CheckDomainAvailability checks if a domain is available for registration
func CheckDomainAvailability(domain string) (bool, error) {
	signatures, err := CheckDomainSignatures(domain)
	if err != nil {
		return false, err
	}

	// Special logging for dc1.de to debug GitHub Actions issue
	if domain == "dc1.de" {
		fmt.Printf("DEBUG dc1.de: Found signatures: %v\n", signatures)
	}



	// If domain is reserved, it's not available
	for _, sig := range signatures {
		if sig == "RESERVED" {
			return false, nil
		}
	}

	// Check if we have any registration signatures
	hasRegistrationSignatures := false
	hasDNSSignatures := false
	hasWHOISSignature := false

	for _, sig := range signatures {
		if sig == "DNS_NS" || sig == "DNS_A" || sig == "DNS_MX" || sig == "DNS_TXT" || sig == "DNS_CNAME" {
			hasDNSSignatures = true
			hasRegistrationSignatures = true
		} else if sig == "WHOIS" {
			hasWHOISSignature = true
			hasRegistrationSignatures = true
		} else if sig == "SSL" {
			hasRegistrationSignatures = true
		}
	}

	// Special logging for dc1.de
	if domain == "dc1.de" {
		fmt.Printf("DEBUG dc1.de: Has registration signatures: %v (DNS: %v, WHOIS: %v)\n",
			hasRegistrationSignatures, hasDNSSignatures, hasWHOISSignature)
	}

	// If we have clear registration signatures, domain is registered
	if hasRegistrationSignatures {
		if domain == "dc1.de" {
			fmt.Printf("DEBUG dc1.de: Returning REGISTERED due to signatures\n")
		}
		return false, nil
	}

	// If no signatures found, check WHOIS as final verification
	// But first, let's check if we have any DNS signatures that might indicate registration
	if domain == "dc1.de" {
		fmt.Printf("DEBUG dc1.de: No registration signatures, performing WHOIS check (DNS signatures available: %v)\n", hasDNSSignatures)
	}

	maxRetries := 3  // Reduced retry count for speed
	for i := 0; i < maxRetries; i++ {
		result, err := whois.Whois(domain)
		if err == nil {
			// Convert WHOIS response to lowercase for case-insensitive matching
			result = strings.ToLower(result)

			// Special logging for dc1.de
			if domain == "dc1.de" {
				fmt.Printf("DEBUG dc1.de: WHOIS response: %s\n", result)
			}

			// Check for access control errors in WHOIS response
			if strings.Contains(result, "connection refused") ||
			   strings.Contains(result, "access control") ||
			   strings.Contains(result, "limit exceeded") {
				if domain == "dc1.de" {
					fmt.Printf("DEBUG dc1.de: WHOIS access denied in response, checking DNS signatures\n")
				}
				// If WHOIS is blocked but we have DNS signatures, consider it registered
				if hasDNSSignatures {
					if domain == "dc1.de" {
						fmt.Printf("DEBUG dc1.de: Has DNS signatures, returning REGISTERED\n")
					}
					return false, nil
				}
				break // Don't continue processing if access is denied
			}

			// Check for indicators that domain is definitely available
			for _, indicator := range availableIndicators {
				if strings.Contains(result, indicator) {
					if domain == "dc1.de" {
						fmt.Printf("DEBUG dc1.de: Found AVAILABLE indicator: %s\n", indicator)
					}
					return true, nil
				}
			}

			// Check for registration indicators
			enhancedRegisteredIndicators := []string{
				"registrar:",
				"registrant:",
				"creation date:",
				"created:",
				"updated date:",
				"updated:",
				"expiration date:",
				"expires:",
				"name server:",
				"nserver:",
				"nameserver:",
				"status: active",
				"status: client",
				"status: ok",
				"status: locked",
				"status: connect",  // Connect status indicates registered domain
				"status:connect",   // Version without space
				"domain name:",
				"domain:",
				"Status: connect",  // Uppercase version
				"nsentry:",         // DENIC specific field
				"changed:",         // DENIC specific field
			}

			for _, indicator := range enhancedRegisteredIndicators {
				if strings.Contains(result, indicator) {
					if domain == "dc1.de" {
						fmt.Printf("DEBUG dc1.de: Found REGISTERED indicator: %s\n", indicator)
					}
					return false, nil
				}
			}

			// Check for special status indicators
			specialStatusIndicators := []string{
				"status: redemptionperiod",
				"status: pendingdelete",
				"status: hold",
				"status: inactive",
				"status: suspended",
				"status: reserved",
				"status: quarantined",
				"status: pending",
				"status: transfer",
				"status: grace",
				"status: autorenewperiod",
				"status: redemption",
				"status: expire",
			}

			for _, indicator := range specialStatusIndicators {
				if strings.Contains(result, indicator) {
					return false, nil
				}
			}
			break
		} else {
			if domain == "dc1.de" {
				fmt.Printf("DEBUG dc1.de: WHOIS attempt %d failed: %v\n", i+1, err)
			}

			// Check if this is an access control error
			if strings.Contains(err.Error(), "connection refused") ||
			   strings.Contains(err.Error(), "access control") ||
			   strings.Contains(err.Error(), "limit exceeded") {
				if domain == "dc1.de" {
					fmt.Printf("DEBUG dc1.de: WHOIS access denied, checking DNS signatures\n")
				}
				// If WHOIS is blocked but we have DNS signatures, consider it registered
				if hasDNSSignatures {
					if domain == "dc1.de" {
						fmt.Printf("DEBUG dc1.de: Has DNS signatures, returning REGISTERED\n")
					}
					return false, nil
				}
				break // Don't retry if access is denied
			}
		}
		if i < maxRetries-1 {
			// Reduced retry interval for speed
			waitTime := time.Duration(1+i) * time.Second
			time.Sleep(waitTime)
		}
	}

	// If we can't determine the status, we need to be careful
	// In GitHub Actions, WHOIS might be blocked, so we can't be sure
	if domain == "dc1.de" {
		fmt.Printf("DEBUG dc1.de: No clear indicators found, returning AVAILABLE (but uncertain due to WHOIS limitations)\n")
	}
	return true, nil
}
