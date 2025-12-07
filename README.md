# Professional XSS Scanner

A professional, automated XSS (Cross-Site Scripting) vulnerability scanner for bug bounty hunting. This tool uses a headless browser to crawl websites, discover forms and URL parameters, test various XSS payloads, and detect vulnerabilities.

## Features

- 🔍 **Automated Crawling**: Discovers forms and URLs automatically
- 🎯 **Multiple Attack Vectors**: Tests 50+ different XSS payloads
- 🛡️ **WAF-Aware**: Uses test markers instead of alert() to bypass WAF detection
- 🚫 **IP Blocking Prevention**: Configurable delays and rate limiting to avoid IP blocks
- 🔄 **Retry Logic**: Exponential backoff for failed requests
- 🥷 **Stealth Mode**: User-agent rotation, realistic headers, and human-like behavior
- 📊 **Advanced Detection**: Detects XSS through test markers, DOM monitoring, console errors, and reflection analysis
- 📝 **Comprehensive Reporting**: Saves results in JSON and human-readable formats
- 🤖 **Headless Browser**: Uses Playwright for reliable browser automation
- 🔒 **Ethical**: Respects robots.txt and includes rate limiting
- 📋 **Detailed Logging**: Comprehensive logging for debugging and analysis

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. Clone or download this repository

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install Playwright browsers:
```bash
playwright install chromium
```

## Usage

### Basic Usage

```bash
python xss_detector.py https://example.com
```

### Advanced Options

```bash
python xss_detector.py https://example.com \
    --depth 3 \
    --pages 100 \
    --output ./scan_results \
    --timeout 60000 \
    --no-headless \
    --min-delay 2.0 \
    --max-delay 5.0 \
    --request-delay 3.0
```

### Command Line Arguments

- `url`: Target URL to scan (required)
- `-d, --depth`: Maximum crawling depth (default: 2)
- `-p, --pages`: Maximum pages to crawl (default: 50)
- `--headless`: Run in headless mode (default: True)
- `--no-headless`: Run with browser visible
- `-o, --output`: Output directory for results (default: results)
- `-t, --timeout`: Request timeout in milliseconds (default: 30000)
- `--waf-aware`: Use WAF-aware mode with test markers (default: True)
- `--no-waf-aware`: Disable WAF-aware mode (use alert() payloads)
- `--min-delay`: Minimum random delay between requests in seconds (default: 1.0)
- `--max-delay`: Maximum random delay between requests in seconds (default: 3.0)
- `--request-delay`: Base delay between requests in seconds (default: 2.0)
- `--max-retries`: Maximum retries for failed requests (default: 3)

### Examples

```bash
# Scan a website with default settings
python xss_detector.py https://target.com

# Deep scan with more pages
python xss_detector.py https://target.com --depth 3 --pages 200

# Scan with visible browser (for debugging)
python xss_detector.py https://target.com --no-headless

# Custom output directory
python xss_detector.py https://target.com -o ./my_results
```

## Output

The scanner generates several output files:

1. **all_results_{timestamp}.json**: All findings (including potential vulnerabilities)
2. **successful_xss_{timestamp}.json**: Confirmed XSS vulnerabilities only
3. **xss_report_{timestamp}.txt**: Human-readable report
4. **xss_scanner.log**: Detailed scan log

### Result Format

```json
{
  "type": "FORM_POST",
  "url": "https://example.com/form",
  "payload": "<script>alert('XSS')</script>",
  "detection_method": "Alert dialog detected: XSS",
  "timestamp": "2024-01-15T10:30:00",
  "context": {
    "parameter": "username"
  }
}
```

## How It Works

1. **Crawling**: The scanner starts from the target URL and crawls the website, respecting robots.txt
2. **Discovery**: Identifies all forms and URL parameters that could be vulnerable
3. **Testing**: Injects various XSS payloads into forms and URL parameters (WAF-aware by default)
4. **Stealth Features**:
   - Random delays between requests (configurable)
   - User-agent rotation
   - Realistic browser headers
   - Human-like behavior (random delays before form submission)
   - Retry logic with exponential backoff
5. **Detection**: Uses multiple methods to detect XSS:
   - WAF-aware: Monitors for test markers in DOM
   - WAF-aware: Checks console messages for test markers
   - WAF-aware: Monitors page errors for error markers
   - Non-WAF: Monitors for JavaScript alert dialogs
   - Observes DOM changes
   - Checks for payload reflection in responses
6. **Reporting**: Saves confirmed vulnerabilities and potential findings

## WAF-Aware Mode

The scanner includes a **WAF-aware mode** (enabled by default) that:

- Uses `test` markers instead of `alert()` to avoid WAF detection
- Detects XSS through test markers in DOM, console, and errors
- Implements time-based detection for delayed payloads
- Uses error-based detection to identify vulnerabilities
- Includes configurable delays to prevent IP blocking

### How WAF-Aware Detection Works

1. **Test Markers**: Instead of `alert('XSS')`, the scanner uses unique test markers like `XSS_TEST_MARKER_2024`
2. **DOM Monitoring**: Monitors DOM changes for test markers and "test" strings
3. **Console Monitoring**: Checks browser console for test markers and errors
4. **Error Detection**: Monitors page errors for error markers
5. **Reflection Analysis**: Checks if payloads are reflected in responses with test context

## XSS Payloads

The scanner tests 50+ XSS payloads including:

- Basic script injection (WAF-aware: uses test markers)
- Event handlers (onerror, onload, etc.) with test markers
- SVG-based payloads
- Encoded payloads
- Filter bypass techniques
- Polyglot payloads
- DOM-based XSS vectors
- Time-based detection payloads
- Error-based detection payloads

## IP Blocking Prevention

The scanner includes several features to prevent IP blocking:

1. **Configurable Delays**: Random delays between requests (default: 1-3 seconds)
2. **Rate Limiting**: Built-in delays to avoid overwhelming servers
3. **Retry Logic**: Exponential backoff for failed requests
4. **Stealth Headers**: Realistic browser headers and user-agent rotation
5. **Human-like Behavior**: Random delays before form submissions

### Recommended Settings for Protected Sites

```bash
# Slower, more stealthy scan
python xss_detector.py https://target.com \
    --min-delay 3.0 \
    --max-delay 6.0 \
    --request-delay 4.0 \
    --max-retries 5
```

## Ethical Considerations

⚠️ **IMPORTANT**: Only use this tool on websites you own or have explicit permission to test. Unauthorized testing may be illegal.

- The scanner respects robots.txt
- Includes rate limiting to avoid overwhelming servers
- Configurable delays to prevent IP blocking
- Designed for authorized security testing only

## Troubleshooting

### Playwright Installation Issues

If you encounter issues with Playwright:

```bash
# Reinstall Playwright
pip install --upgrade playwright
playwright install chromium
```

### Timeout Errors

If you get timeout errors, increase the timeout:

```bash
python xss_detector.py https://example.com --timeout 60000
```

### Browser Issues

If the browser doesn't launch:

1. Make sure Chromium is installed: `playwright install chromium`
2. Try running without headless mode: `--no-headless`
3. Check the logs in `xss_scanner.log`

## Contributing

Contributions are welcome! Please ensure:

1. Code follows PEP 8 style guidelines
2. All new features include tests
3. Documentation is updated
4. Ethical considerations are maintained

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any website.

## Disclaimer

This tool is for authorized security testing only. The authors are not responsible for any misuse of this tool. Always obtain proper authorization before testing any website or application.

## Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Happy Bug Hunting! 🐛🔍**

# xss-automation
