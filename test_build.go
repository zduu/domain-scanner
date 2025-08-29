package main

import (
	"fmt"
	"os"
)

// Simple test to verify the build works
func main() {
	fmt.Println("Testing build...")
	
	// Test charset generation logic
	patterns := []string{"D", "d", "a"}
	
	for _, pattern := range patterns {
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
			fmt.Printf("Invalid pattern: %s\n", pattern)
			os.Exit(1)
		}
		
		fmt.Printf("Pattern %s: charset=%s, maxBatches=%d\n", pattern, charset, maxBatches)
		
		// Test first few characters
		for i := 0; i < 3 && i < len(charset); i++ {
			char := string(charset[i])
			fmt.Printf("  Batch %d: %s\n", i, char)
		}
		fmt.Println()
	}
	
	fmt.Println("Build test completed successfully!")
}
