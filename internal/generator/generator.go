package generator

import (
	"fmt"
	"os"
	"strings"
	"time"

	"domain-scanner/internal/types"
	"github.com/dlclark/regexp2"
)

// GenerateDomains returns a streaming domain channel instead of generating all domains at once
func GenerateDomains(length int, suffix string, pattern string, regexFilter string, regexMode types.RegexMode) <-chan string {
	letters := "abcdefghijklmnopqrstuvwxyz"
	numbers := "0123456789"

	var regex *regexp2.Regexp
	var err error
	if regexFilter != "" {
		// Validate regex complexity
		if err := validateRegexComplexity(regexFilter); err != nil {
			fmt.Printf("Regex pattern rejected: %v\n", err)
			os.Exit(1)
		}

		regex, err = regexp2.Compile(regexFilter, regexp2.None)
		if err != nil {
			fmt.Printf("Invalid regex pattern: %v\n", err)
			os.Exit(1)
		}

		// Set timeout protection against ReDoS attacks
		regex.MatchTimeout = 100 * time.Millisecond
	}

	domainChan := make(chan string, 1000) // Buffer pool for better performance

	go func() {
		defer close(domainChan)

		switch pattern {
		case "d":
			generateCombinationsIterative(domainChan, numbers, length, suffix, regex, regexMode)
		case "D":
			generateCombinationsIterative(domainChan, letters, length, suffix, regex, regexMode)
		case "a":
			generateCombinationsIterative(domainChan, letters+numbers, length, suffix, regex, regexMode)
		default:
			fmt.Println("Invalid pattern. Use -d for numbers, -D for letters, -a for alphanumeric")
			os.Exit(1)
		}
	}()

	return domainChan
}

// generateCombinationsIterative uses iterative method instead of recursive to prevent stack overflow
func generateCombinationsIterative(domainChan chan<- string, charset string, length int, suffix string, regex *regexp2.Regexp, regexMode types.RegexMode) {
	charsetSize := len(charset)
	if charsetSize == 0 || length <= 0 {
		return
	}

	// Use counter method to generate combinations
	total := 1
	for i := 0; i < length; i++ {
		total *= charsetSize
	}

	for counter := 0; counter < total; counter++ {
		current := ""
		temp := counter

		// Generate domain string from counter
		for i := 0; i < length; i++ {
			current = string(charset[temp%charsetSize]) + current
			temp /= charsetSize
		}

		domain := current + suffix
		var match bool
		switch regexMode {
		case types.RegexModeFull:
			if regex == nil {
				match = true
			} else {
				var err error
				match, err = safeRegexMatch(regex, domain)
				if err != nil {
					// Skip domain on regex matching error
					match = false
				}
			}
		case types.RegexModePrefix:
			if regex == nil {
				match = true
			} else {
				var err error
				match, err = safeRegexMatch(regex, current)
				if err != nil {
					// Skip domain on regex matching error
					match = false
				}
			}
		}

		if match {
			domainChan <- domain
		}
	}
}

// CalculateDomainsCount calculates the total number of domains for given pattern and length
func CalculateDomainsCount(length int, pattern string) int {
	var charsetSize int
	switch pattern {
	case "d": // Pure numbers
		charsetSize = 10 // 0-9
	case "D": // Pure letters
		charsetSize = 26 // a-z
	case "a": // Alphanumeric
		charsetSize = 36 // a-z + 0-9
	default:
		return 0
	}

	total := 1
	for i := 0; i < length; i++ {
		total *= charsetSize
	}
	return total
}

// validateRegexComplexity checks regex complexity to prevent potential ReDoS attacks
func validateRegexComplexity(pattern string) error {
	// Check length limit
	if len(pattern) > 200 {
		return fmt.Errorf("regex pattern too long (max 200 characters)")
	}

	// Check known dangerous patterns
	dangerousPatterns := []string{
		"(.*)*",       // Nested quantifiers
		"(.+)+",       // Nested quantifiers
		"(a+)+",       // Classic ReDoS pattern
		"(a*)*",       // Nested asterisks
		"(.{0,})*",    // Complex nesting
		"(\\w+)*\\w*", // Complex word matching
	}

	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return fmt.Errorf("detected potentially dangerous regex pattern: %s", dangerous)
		}
	}

	// Check nested quantifier count
	nestedCount := strings.Count(pattern, "+") + strings.Count(pattern, "*")
	if nestedCount > 5 {
		return fmt.Errorf("too many quantifiers in regex pattern (max 5)")
	}

	return nil
}

// safeRegexMatch safely executes regex matching with timeout and error handling
func safeRegexMatch(regex *regexp2.Regexp, input string) (bool, error) {
	if regex == nil {
		return true, nil
	}

	// Ensure timeout is set
	if regex.MatchTimeout == 0 {
		regex.MatchTimeout = 100 * time.Millisecond
	}

	match, err := regex.MatchString(input)
	if err != nil {
		return false, fmt.Errorf("regex matching failed for pattern '%s' with input '%s': %w", regex.String(), input, err)
	}

	return match, nil
}
