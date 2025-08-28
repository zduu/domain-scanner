package worker

import (
	"time"

	"domain-scanner/internal/domain"
	"domain-scanner/internal/types"
)

// Worker processes domain availability checks
func Worker(id int, jobs <-chan string, results chan<- types.DomainResult, delay time.Duration) {
	for domainName := range jobs {
		available, err := domain.CheckDomainAvailability(domainName)
		signatures, _ := domain.CheckDomainSignatures(domainName)
		
		// Check for special status (placeholder for future implementation)
		specialStatus := ""
		
		results <- types.DomainResult{
			Domain:        domainName,
			Available:     available,
			Error:         err,
			Signatures:    signatures,
			SpecialStatus: specialStatus,
		}
		time.Sleep(delay)
	}
}
