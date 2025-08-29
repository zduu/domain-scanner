package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	generateBatchConfigs()
}

func generateBatchConfigs() {
	// Parse command line arguments
	args := os.Args[1:]
	batchStart := 0
	batchSize := 26
	baseDomain := ".de"
	domainLength := 4
	pattern := "D"
	outputDir := "./results"
	configDir := "./config"
	
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "-batch-start":
			if val, err := strconv.Atoi(args[i+1]); err == nil {
				batchStart = val
			}
		case "-batch-size":
			if val, err := strconv.Atoi(args[i+1]); err == nil {
				batchSize = val
			}
		case "-base-domain":
			baseDomain = args[i+1]
		case "-domain-length":
			if val, err := strconv.Atoi(args[i+1]); err == nil {
				domainLength = val
			}
		case "-pattern":
			pattern = args[i+1]
		case "-output-dir":
			outputDir = args[i+1]
		case "-config-dir":
			configDir = args[i+1]
		}
	}
	
	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Printf("Error creating config directory: %v\n", err)
		os.Exit(1)
	}
	
	// Generate configurations
	var charset string
	var maxBatches int

	switch pattern {
	case "D": // Letters only
		charset = "abcdefghijklmnopqrstuvwxyz"
		maxBatches = 26
	case "d": // Digits only
		charset = "0123456789"
		maxBatches = 10
	case "a": // Alphanumeric - include both letters and digits for complete coverage
		charset = "abcdefghijklmnopqrstuvwxyz0123456789"
		maxBatches = 36
	default:
		fmt.Printf("Invalid pattern: %s. Use D for letters, d for digits, a for alphanumeric\n", pattern)
		os.Exit(1)
	}

	startIdx := batchStart
	endIdx := batchStart + batchSize

	if endIdx > maxBatches {
		endIdx = maxBatches
	}
	
	fmt.Printf("Generating batch configurations...\n")
	fmt.Printf("Batch start: %d\n", startIdx)
	fmt.Printf("Batch size: %d\n", batchSize)
	fmt.Printf("Base domain: %s\n", baseDomain)
	fmt.Printf("Domain length: %d\n", domainLength)
	fmt.Printf("Pattern: %s\n", pattern)
	fmt.Printf("Config directory: %s\n", configDir)
	fmt.Printf("Output directory: %s\n", outputDir)
	
	for i := startIdx; i < endIdx; i++ {
		char := string(letters[i])
		configPath := fmt.Sprintf("%s/config_batch_%s.toml", configDir, char)
		batchOutputDir := fmt.Sprintf("%s/batch_%s", outputDir, char)

		// Create regex based on pattern
		regex := ""
		switch pattern {
		case "D": // Letters only
			regex = fmt.Sprintf("^%s.*", char)
		case "d": // Digits only
			// For digits, create regex that matches domains starting with this digit
			regex = fmt.Sprintf("^%s.*", char)
		case "a": // Alphanumeric
			// For alphanumeric, use letters for batching but allow both letters and digits
			regex = fmt.Sprintf("^%s[a-z0-9].*", char)
		}
		
		var charType string
		switch pattern {
		case "D":
			charType = "letter"
		case "d":
			charType = "digit"
		case "a":
			charType = "character"
		}

		content := fmt.Sprintf(`# Batch domain scanner configuration for %s "%s"
# Auto-generated for batch processing
# Generated at: $(date)

# Domain configuration
[domain]
# Domain name length
length = %d

# Domain suffix (e.g., .de, .com)
suffix = "%s"

# Domain pattern:
# D: Pure letters (e.g., abc.de)
# d: Pure numbers (e.g., 123.de)
# a: Alphanumeric (e.g., a1b.de)
pattern = "%s"

# Regular expression filter for domains starting with "%s"
# This ensures only domains starting with this %s are scanned
regex_filter = "%s"

# Scanner behavior configuration
[scanner]
# Delay between queries in milliseconds (increased to prevent rate limiting)
delay = 1000

# Number of concurrent workers (reduced to prevent rate limiting)
workers = 8

# Show registered domains in output
show_registered = true

# Enabled detection methods (optimized for speed)
[scanner.methods]
# Check DNS records (NS, A, MX, TXT, CNAME) - fast
dns_check = true

# Check WHOIS information - primary method
whois_check = true

# Check SSL certificates - disabled for speed
ssl_check = false

# Check HTTP responses - disabled
http_check = false

# Output configuration
[output]
# Available domains file name template
available_file = "available_domains_batch_%s_{pattern}_{length}_{suffix}.txt"

# Registered domains file name template
registered_file = "registered_domains_batch_%s_{pattern}_{length}_{suffix}.txt"

# Special status domains file name template
special_status_file = "special_status_domains_batch_%s_{pattern}_{length}_{suffix}.txt"

# Output directory for this batch
output_dir = "%s"

# Show detailed results in console (enabled for debugging)
verbose = true

# Regex filter explanation:
# ^%s.* - Matches domains starting with %s "%s"
# This reduces the domain space significantly for faster scanning
# Example for %s 'a': "a.*" matches "ab.de", "abc.de", etc.
`, charType, char, domainLength, baseDomain, pattern, char, charType, regex, char, char, char, batchOutputDir, char, charType, char, charType)
		
		// Write config file
		err := os.WriteFile(configPath, []byte(content), 0644)
		if err != nil {
			fmt.Printf("Error writing config file %s: %v\n", configPath, err)
			continue
		}
		
		// Create output directory
		if err := os.MkdirAll(batchOutputDir, 0755); err != nil {
			fmt.Printf("Error creating output directory %s: %v\n", batchOutputDir, err)
			continue
		}
		
		fmt.Printf("Generated: %s -> %s\n", configPath, batchOutputDir)
	}
	
	fmt.Printf("\nBatch configuration generation completed!\n")
	fmt.Printf("Generated %d configurations for batches %d to %d\n", endIdx-startIdx, startIdx, endIdx-1)
	fmt.Printf("Config directory: %s\n", configDir)
	fmt.Printf("Output base directory: %s\n", outputDir)
	
	// Create a batch index file
	indexFile := fmt.Sprintf("%s/batch_index.txt", configDir)
	indexContent := fmt.Sprintf(`# Batch Configuration Index
# Auto-generated batch configuration summary
# Generated at: $(date)

# Batch Configuration Summary
===================================
Batch Start: %d
Batch End: %d
Total Batches: %d
Base Domain: %s
Domain Length: %d
Pattern: %s
Config Directory: %s
Output Directory: %s

# Generated Configuration Files
===================================`, startIdx, endIdx-1, endIdx-startIdx, baseDomain, domainLength, pattern, configDir, outputDir)
	
	for i := startIdx; i < endIdx; i++ {
		char := string(charset[i])
		configPath := fmt.Sprintf("config_batch_%s.toml", char)
		outputPath := fmt.Sprintf("%s/batch_%s", outputDir, char)
		var charType string
		switch pattern {
		case "D":
			charType = "Letter"
		case "d":
			charType = "Digit"
		case "a":
			charType = "Character"
		}
		indexContent += fmt.Sprintf("\nBatch %2d: %s '%s' -> %s\n  Config: %s\n  Output: %s\n",
			i-startIdx+1, charType, char, char, configPath, outputPath)
	}
	
	if err := os.WriteFile(indexFile, []byte(indexContent), 0644); err != nil {
		fmt.Printf("Warning: Could not write index file: %v\n", err)
	} else {
		fmt.Printf("Index file created: %s\n", indexFile)
	}
}