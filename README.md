# crlfroot
crlfroot

## Installation and Usage:

```bash
# 1. Initialize module
go mod init crlfroot

# 2. Download dependencies
go mod download

# 3. Build the scanner
go build -o crflroot

# 4. Run basic scan
./crlfroot -u https://example.com

# 5. Scan with authentication
./crlfroot -u https://example.com --auth

# 6. Scan multiple URLs from file
./crlfroot -uf urls.txt -t 100 -r 20

# 7. Use custom configuration
./crlfroot -u https://example.com -c config.yaml

# 8. Disable spidering
./crlfroot -u https://example.com --no-spider

# 9. Verbose mode
./crlfroot -u https://example.com -v
```

## Features:

1. **Advanced Spidering**:
   - URL extraction from HTML, JavaScript, and comments
   - Form detection and analysis
   - Technology fingerprinting
   - Recursive crawling with depth control

2. **CRLF Injection Detection**:
   - Multiple injection points (headers, parameters, paths, forms)
   - Advanced payloads with bypass techniques
   - Unicode and double-encoding bypasses
   - Real-time detection with evidence extraction

3. **Authentication Support**:
   - Basic authentication
   - Bearer tokens
   - Form-based authentication
   - Session management
   - Cookie handling

4. **Header Manipulation**:
   - Custom headers
   - Security header testing
   - Random header injection
   - Header fuzzing

5. **Comprehensive Reporting**:
   - JSON, HTML, Markdown, CSV outputs
   - Detailed evidence and request/response logging
   - Severity classification
   - CVSS scoring

6. **Performance Features**:
   - Concurrent scanning with configurable threads
   - Rate limiting
   - Connection pooling
   - Automatic retries
   - Proxy support

This is a production-ready CRLF injection scanner with enterprise features for comprehensive web application security testing.

## NEXT UPDATE 

* 1 ADD PROXY INTERSEPT
* 2 ADD MULTI MATCH REPLACE CONFIG ATTACK
* 3 ADD MULTI PAYLOAD BYPASS BY PAYLAOD ENGINE
* 4 AUTO SEND ALL VULN TO TELEGRAM AND 0AUTH WEBHOOK EX: GITHUB + DISCORD
* 5 ENJOY BUGBOUTY WITH WORKFLOW AUTOMATION 
