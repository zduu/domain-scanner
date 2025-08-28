package types

// DomainResult represents the result of a domain availability check
type DomainResult struct {
	Domain       string
	Available    bool
	Error        error
	Signatures   []string
	SpecialStatus string
}

// RegexMode defines how regex patterns should be applied
type RegexMode int

const (
	RegexModeFull RegexMode = iota
	RegexModePrefix
)

// Config represents the application configuration
type Config struct {
	Domain struct {
		Length      int    `toml:"length"`
		Suffix      string `toml:"suffix"`
		Pattern     string `toml:"pattern"`
		RegexFilter string `toml:"regex_filter"`
	} `toml:"domain"`

	Scanner struct {
		Delay         int  `toml:"delay"`
		Workers       int  `toml:"workers"`
		ShowRegistered bool `toml:"show_registered"`
		Methods       struct {
			DNSCheck  bool `toml:"dns_check"`
			WHOISCheck bool `toml:"whois_check"`
			SSLCheck  bool `toml:"ssl_check"`
			HTTPCheck bool `toml:"http_check"`
		} `toml:"methods"`
	} `toml:"scanner"`

	Output struct {
		AvailableFile    string `toml:"available_file"`
		RegisteredFile   string `toml:"registered_file"`
		SpecialStatusFile string `toml:"special_status_file"`
		OutputDir        string `toml:"output_dir"`
		Verbose          bool   `toml:"verbose"`
	} `toml:"output"`
}
