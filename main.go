package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"domain-scanner/internal/config"
	"domain-scanner/internal/domain"
	"domain-scanner/internal/generator"
	"domain-scanner/internal/types"
	"domain-scanner/internal/worker"
)

// Create a global variable to hold the config
var appConfig *types.Config









func printHelp() {
	fmt.Println("Domain Scanner - A tool to check domain availability")
	fmt.Println("\nUsage:")
	fmt.Println("  go run main.go [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  -l int      Domain length (default: 3)")
	fmt.Println("  -s string   Domain suffix (default: .li)")
	fmt.Println("  -p string   Domain pattern:")
	fmt.Println("              d: Pure numbers (e.g., 123.li)")
	fmt.Println("              D: Pure letters (e.g., abc.li)")
	fmt.Println("              a: Alphanumeric (e.g., a1b.li)")
	fmt.Println("  -r string   Regex filter for domain names")
	fmt.Println("  -regex-mode string Regex matching mode (default: full)")
	fmt.Println("    full: Match entire domain name")
	fmt.Println("    prefix: Match only domain name prefix")
	fmt.Println("  -delay int  Delay between queries in milliseconds (default: 1000)")
	fmt.Println("  -workers int Number of concurrent workers (default: 10)")
	fmt.Println("  -show-registered Show registered domains in output (default: false)")
	fmt.Println("  -config string  Path to config file (default: config.toml)")
	fmt.Println("  -h          Show help information")
	fmt.Println("\nExamples:")
	fmt.Println("  1. Check 3-letter .li domains with 20 workers:")
	fmt.Println("     go run main.go -l 3 -s .li -p D -workers 20")
	fmt.Println("\n  2. Check domains with custom delay and workers:")
	fmt.Println("     go run main.go -l 3 -s .li -p D -delay 500 -workers 15")
	fmt.Println("\n  3. Show both available and registered domains:")
	fmt.Println("     go run main.go -l 3 -s .li -p D -show-registered")
	fmt.Println("\n  4. Use config file:")
	fmt.Println("     go run main.go -config config.toml")
	fmt.Println("\n  5. Use regex filter with full domain matching:")
	fmt.Println("     go run main.go -l 3 -s .li -p D -r \"^[a-z]{2}[0-9]$\" -regex-mode full")
	fmt.Println("\n  6. Use regex filter with prefix matching:")
	fmt.Println("     go run main.go -l 3 -s .li -p D -r \"^[a-z]{2}\" -regex-mode prefix")
}

func showMOTD() {
	fmt.Println("\033[1;36m") // Cyan color
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    Domain Scanner v1.3.2                   ║")
	fmt.Println("║                                                            ║")
	fmt.Println("║  A powerful tool for checking domain name availability     ║")
	fmt.Println("║                                                            ║")
	fmt.Println("║  Developer: www.ict.run                                    ║")
	fmt.Println("║  GitHub:    https://github.com/xuemian168/domain-scanner   ║")
	fmt.Println("║                                                            ║")
	fmt.Println("║  License:   AGPL-3.0                                       ║")
	fmt.Println("║  Copyright © 2025                                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("\033[0m") // Reset color
	fmt.Println()
}

func main() {
	// Show MOTD
	showMOTD()

	// Define command line flags
	length := flag.Int("l", 3, "Domain length")
	suffix := flag.String("s", ".li", "Domain suffix")
	pattern := flag.String("p", "D", "Domain pattern (d: numbers, D: letters, a: alphanumeric)")
	regexFilter := flag.String("r", "", "Regex filter for domain names")
	delay := flag.Int("delay", 1000, "Delay between queries in milliseconds")
	workers := flag.Int("workers", 10, "Number of concurrent workers")
	showRegistered := flag.Bool("show-registered", false, "Show registered domains in output")
	configPath := flag.String("config", "config/config.toml", "Path to config file")
	help := flag.Bool("h", false, "Show help information")
	regexMode := flag.String("regex-mode", "full", "Regex match mode: 'full' or 'prefix'")
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// Load config file if specified and exists
	if *configPath != "" {
		if _, err := os.Stat(*configPath); err == nil {
			var err error
			appConfig, err = config.LoadConfig(*configPath)
			if err != nil {
				fmt.Printf("Error loading config file: %v\n", err)
				os.Exit(1)
			}

			// Set global config for domain checker
			domain.SetConfig(appConfig)

			// Override command line flags with config values only if they weren't explicitly set
			if flag.Lookup("l").Value.String() == "3" { // Default value
				*length = appConfig.Domain.Length
			}
			if flag.Lookup("s").Value.String() == ".li" { // Default value
				*suffix = appConfig.Domain.Suffix
			}
			if flag.Lookup("p").Value.String() == "D" { // Default value
				*pattern = appConfig.Domain.Pattern
			}
			if *regexFilter == "" && appConfig.Domain.RegexFilter != "" {
				*regexFilter = appConfig.Domain.RegexFilter
			}
			if flag.Lookup("delay").Value.String() == "1000" { // Default value
				*delay = appConfig.Scanner.Delay
			}
			if flag.Lookup("workers").Value.String() == "10" { // Default value
				*workers = appConfig.Scanner.Workers
			}
			if flag.Lookup("show-registered").Value.String() == "false" { // Default value
				*showRegistered = appConfig.Scanner.ShowRegistered
			}
		} else {
			fmt.Printf("Config file %s not found, using command line parameters\n", *configPath)
		}
	}

	// Ensure suffix starts with a dot
	if !strings.HasPrefix(*suffix, ".") {
		*suffix = "." + *suffix
	}

	// Determine regex mode
	var regexModeEnum types.RegexMode
	if *regexMode == "full" {
		regexModeEnum = types.RegexModeFull
	} else if *regexMode == "prefix" {
		regexModeEnum = types.RegexModePrefix
	} else {
		fmt.Println("Invalid regex-mode. Use 'full' or 'prefix'")
		os.Exit(1)
	}

	domainChan := generator.GenerateDomains(*length, *suffix, *pattern, *regexFilter, regexModeEnum)
	availableDomains := []string{}
	registeredDomains := []string{}

	// Calculate total domains count (base count, may be reduced by regex filter)
	baseDomainCount := generator.CalculateDomainsCount(*length, *pattern)
	fmt.Printf("Checking domains with pattern %s and length %d using %d workers...\n",
		*pattern, *length, *workers)
	if *regexFilter != "" {
		fmt.Printf("Using regex filter: %s (base count: %d domains)\n", *regexFilter, baseDomainCount)
	} else {
		fmt.Printf("Total domains to check: %d\n", baseDomainCount)
	}

	// Create channels for jobs and results
	jobs := make(chan string, 1000)
	results := make(chan types.DomainResult, 1000)

	// Start workers
	for w := 1; w <= *workers; w++ {
		go worker.Worker(w, jobs, results, time.Duration(*delay)*time.Millisecond)
	}

	// Send jobs from domain generator
	var totalGenerated int
	go func() {
		defer close(jobs)
		domainCount := 0
		for domain := range domainChan {
			domainCount++
			jobs <- domain
		}
		totalGenerated = domainCount

	}()

	// Create a channel for domain status messages
	statusChan := make(chan string, 1000)

	// Start a goroutine to print status messages
	go func() {
		for msg := range statusChan {
			fmt.Println(msg)
		}
	}()

	// Collect results
	var wg sync.WaitGroup
	var totalProcessed int
	wg.Add(1)
	go func() {
		defer wg.Done()
		processedCount := 0
		for result := range results {
			processedCount++
			totalProcessed = processedCount // Update global counter
			progress := fmt.Sprintf("[%d]", processedCount)
			if result.Error != nil {
				statusChan <- fmt.Sprintf("%s Error checking domain %s: %v", progress, result.Domain, result.Error)
				continue
			}

			if result.Available {
				statusChan <- fmt.Sprintf("%s Domain %s is AVAILABLE!", progress, result.Domain)
				availableDomains = append(availableDomains, result.Domain)
			} else {
				// Always count registered domains, but only show if requested
				if *showRegistered {
					sigStr := strings.Join(result.Signatures, ", ")
					statusChan <- fmt.Sprintf("%s Domain %s is REGISTERED [%s]", progress, result.Domain, sigStr)
					registeredDomains = append(registeredDomains, result.Domain)
				}
			}
		}
		close(statusChan)
	}()

	// Monitor task completion
	go func() {
		// Wait for all jobs to be sent
		for totalGenerated == 0 {
			time.Sleep(100 * time.Millisecond)
		}

		// Wait for all results to be processed
		for totalProcessed < totalGenerated {
			time.Sleep(100 * time.Millisecond)
		}

		// Give a bit more time for final processing
		time.Sleep(1 * time.Second)
		close(results)
	}()

	wg.Wait()

	// Save available domains to file
	availableFile := fmt.Sprintf("available_domains_%s_%d_%s.txt", *pattern, *length, strings.TrimPrefix(*suffix, "."))
	if appConfig != nil && appConfig.Output.AvailableFile != "" {
		availableFile = strings.Replace(appConfig.Output.AvailableFile, "{pattern}", *pattern, -1)
		availableFile = strings.Replace(availableFile, "{length}", fmt.Sprintf("%d", *length), -1)
		availableFile = strings.Replace(availableFile, "{suffix}", strings.TrimPrefix(*suffix, "."), -1)
	}

	// Create output directory if specified in config
	outputDir := "."
	if appConfig != nil && appConfig.Output.OutputDir != "" {
		outputDir = appConfig.Output.OutputDir
		// Always create directory if it doesn't exist, even if it's "."
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			os.Exit(1)
		}
		availableFile = outputDir + "/" + availableFile
	}

	file, err := os.Create(availableFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fmt.Printf("Error closing file: %v\n", closeErr)
		}
	}()

	for _, domain := range availableDomains {
		_, err := file.WriteString(domain + "\n")
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			os.Exit(1)
		}
	}

	// Save registered domains to file only if show-registered is true
	registeredFile := fmt.Sprintf("registered_domains_%s_%d_%s.txt", *pattern, *length, strings.TrimPrefix(*suffix, "."))
	if *showRegistered {
		if appConfig != nil && appConfig.Output.RegisteredFile != "" {
			registeredFile = strings.Replace(appConfig.Output.RegisteredFile, "{pattern}", *pattern, -1)
			registeredFile = strings.Replace(registeredFile, "{length}", fmt.Sprintf("%d", *length), -1)
			registeredFile = strings.Replace(registeredFile, "{suffix}", strings.TrimPrefix(*suffix, "."), -1)
		}

		// Use output directory if specified in config
		if appConfig != nil && appConfig.Output.OutputDir != "" {
			registeredFile = outputDir + "/" + registeredFile
		}

		regFile, err := os.Create(registeredFile)
		if err != nil {
			fmt.Printf("Error creating registered domains file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if closeErr := regFile.Close(); closeErr != nil {
				fmt.Printf("Error closing registered domains file: %v\n", closeErr)
			}
		}()

		for _, domain := range registeredDomains {
			_, err := regFile.WriteString(domain + "\n")
			if err != nil {
				fmt.Printf("Error writing to registered domains file: %v\n", err)
				os.Exit(1)
			}
		}
	}

	fmt.Printf("\n\nResults saved to:\n")
	fmt.Printf("- Available domains: %s\n", availableFile)
	if *showRegistered {
		fmt.Printf("- Registered domains: %s\n", registeredFile)
	}
	fmt.Printf("\nSummary:\n")
	fmt.Printf("- Total domains processed: %d\n", totalProcessed)
	fmt.Printf("- Available domains: %d\n", len(availableDomains))
	if *showRegistered {
		fmt.Printf("- Registered domains: %d\n", len(registeredDomains))
	} else {
		registeredCount := totalProcessed - len(availableDomains)
		fmt.Printf("- Registered domains: %d (not saved to file)\n", registeredCount)
	}
}
