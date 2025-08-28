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
		maxRetries := 5  // Increased retry count
		for i := 0; i < maxRetries; i++ {
			if globalConfig != nil && globalConfig.Output.Verbose {
				fmt.Printf("DEBUG: WHOIS attempt %d/%d for %s\n", i+1, maxRetries, domain)
			}
			
			result, err := whois.Whois(domain)
			if err == nil {
				whoisResult = result
				break
			}
			if i < maxRetries-1 {
				// Increased retry interval to avoid rate limiting
				waitTime := time.Duration(2+i*2) * time.Second
				if globalConfig != nil && globalConfig.Output.Verbose {
					fmt.Printf("DEBUG: Waiting %v before retry for %s\n", waitTime, domain)
				}
				time.Sleep(waitTime)
			}
		}

		if whoisResult != "" {
			// Convert WHOIS response to lowercase for case-insensitive matching
			result := strings.ToLower(whoisResult)

			if globalConfig != nil && globalConfig.Output.Verbose {
				fmt.Printf("DEBUG: WHOIS response for %s (first 200 chars): %s\n", domain, 
					result[:min(200, len(result))])
			}

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
	// Add debug logging
	if globalConfig != nil && globalConfig.Output.Verbose {
		fmt.Printf("DEBUG: Checking domain availability for %s\n", domain)
	}

	signatures, err := CheckDomainSignatures(domain)
	if err != nil {
		if globalConfig != nil && globalConfig.Output.Verbose {
			fmt.Printf("DEBUG: Error getting signatures for %s: %v\n", domain, err)
		}
		return false, err
	}

	if globalConfig != nil && globalConfig.Output.Verbose {
		fmt.Printf("DEBUG: Found signatures for %s: %v\n", domain, signatures)
	}

	// If domain is reserved, it's not available
	for _, sig := range signatures {
		if sig == "RESERVED" {
			return false, nil
		}
	}

	// If any other signature is found, domain is registered
	if len(signatures) > 0 {
		return false, nil
	}

	// If no signatures found, check WHOIS as final verification with retry
	if globalConfig != nil && globalConfig.Output.Verbose {
		fmt.Printf("DEBUG: No signatures found for %s, performing final WHOIS check\n", domain)
	}

	maxRetries := 5  // Increased retry count
	for i := 0; i < maxRetries; i++ {
		if globalConfig != nil && globalConfig.Output.Verbose {
			fmt.Printf("DEBUG: WHOIS attempt %d/%d for %s\n", i+1, maxRetries, domain)
		}

		result, err := whois.Whois(domain)
		if err == nil {
			// Convert WHOIS response to lowercase for case-insensitive matching
			result = strings.ToLower(result)

			if globalConfig != nil && globalConfig.Output.Verbose {
				fmt.Printf("DEBUG: WHOIS response for %s (first 200 chars): %s\n", domain,
					result[:min(200, len(result))])
			}

			// Check for indicators that domain is definitely available
			for _, indicator := range availableIndicators {
				if strings.Contains(result, indicator) {
					if globalConfig != nil && globalConfig.Output.Verbose {
						fmt.Printf("DEBUG: Found available indicator '%s' for %s\n", indicator, domain)
					}
					return true, nil
				}
			}

			// Check for registration indicators as a secondary check
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
					if globalConfig != nil && globalConfig.Output.Verbose {
						fmt.Printf("DEBUG: Found registered indicator '%s' for %s\n", indicator, domain)
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
			if globalConfig != nil && globalConfig.Output.Verbose {
				fmt.Printf("DEBUG: WHOIS attempt %d failed for %s: %v\n", i+1, domain, err)
			}
		}
		if i < maxRetries-1 {
			// Increased retry interval to avoid rate limiting
			waitTime := time.Duration(2+i*2) * time.Second
			if globalConfig != nil && globalConfig.Output.Verbose {
				fmt.Printf("DEBUG: Waiting %v before retry for %s\n", waitTime, domain)
			}
			time.Sleep(waitTime)
		}
	}

	// If we can't determine the status, assume the domain is available
	if globalConfig != nil && globalConfig.Output.Verbose {
		fmt.Printf("DEBUG: Could not determine status for %s, assuming available\n", domain)
	}
	return true, nil
}
