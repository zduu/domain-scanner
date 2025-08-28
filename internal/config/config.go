package config

import (
	"domain-scanner/internal/types"
	"github.com/BurntSushi/toml"
)

// LoadConfig loads configuration from a TOML file
func LoadConfig(configPath string) (*types.Config, error) {
	config := &types.Config{}
	if _, err := toml.DecodeFile(configPath, config); err != nil {
		return nil, err
	}
	
	// Set default values if not specified in config
	if config.Domain.Length == 0 {
		config.Domain.Length = 3
	}
	
	if config.Domain.Suffix == "" {
		config.Domain.Suffix = ".li"
	}
	
	if config.Domain.Pattern == "" {
		config.Domain.Pattern = "D"
	}
	
	if config.Scanner.Delay == 0 {
		config.Scanner.Delay = 1000
	}
	
	if config.Scanner.Workers == 0 {
		config.Scanner.Workers = 10
	}
	
	// Set default values for scanner methods
	if !config.Scanner.Methods.DNSCheck && !config.Scanner.Methods.WHOISCheck && 
	   !config.Scanner.Methods.SSLCheck && !config.Scanner.Methods.HTTPCheck {
		config.Scanner.Methods.DNSCheck = true
		config.Scanner.Methods.WHOISCheck = true
		config.Scanner.Methods.SSLCheck = true
		config.Scanner.Methods.HTTPCheck = false // Disabled by default
	}
	
	if config.Output.AvailableFile == "" {
		config.Output.AvailableFile = "available_domains_{pattern}_{length}_{suffix}.txt"
	}
	
	if config.Output.RegisteredFile == "" {
		config.Output.RegisteredFile = "registered_domains_{pattern}_{length}_{suffix}.txt"
	}
	
	if config.Output.SpecialStatusFile == "" {
		config.Output.SpecialStatusFile = "special_status_domains_{pattern}_{length}_{suffix}.txt"
	}
	
	if config.Output.OutputDir == "" {
		config.Output.OutputDir = "."
	}
	
	return config, nil
}
