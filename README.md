# CVE-2023-44487 HTTP/2 Rapid Reset Testing Tool

A comprehensive Python testing tool for **CVE-2023-44487**, the HTTP/2 Rapid Reset vulnerability. This tool implements the attack vector to test server resilience against this critical DoS vulnerability.

## ⚠️ **IMPORTANT DISCLAIMER**

**This tool is for educational and authorized testing purposes ONLY!**

- Only use against systems you own or have explicit written permission to test
- Unauthorized use may be illegal and could cause service disruption
- The tool performs a Denial of Service attack that can impact server availability
- Always ensure you have proper authorization before testing

## 🔍 About CVE-2023-44487

CVE-2023-44487, also known as "HTTP/2 Rapid Reset," is a critical vulnerability in the HTTP/2 protocol that allows attackers to:

- Cause denial of service by rapidly sending and canceling HTTP/2 streams
- Consume excessive server resources with minimal client resources
- Bypass many traditional rate limiting mechanisms
- Affect major web servers and load balancers

**CVSS Score:** 7.5 (High)

**Impact:** Denial of Service, Resource Exhaustion

## 🚀 Features

- **Pure Python Implementation**: No external dependencies required
- **Asynchronous Operation**: Efficient concurrent testing
- **Configurable Parameters**: Customizable connection count and request volume
- **Detailed Reporting**: Comprehensive test results and vulnerability assessment
- **Safety Controls**: Built-in limits and authorization checks
- **Verbose Logging**: Detailed operation tracking for analysis

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (uses only Python standard library)

## 📖 Installation

1. **Clone or download the script:**
```bash
git clone <repository-url>
cd cve-2023-44487-tester
```

2. **Make the script executable:**
```bash
chmod +x rapid_reset_test.py
```

3. **Verify Python version:**
```bash
python3 --version  # Should be 3.7+
```

## 🔧 Usage

### Basic Usage

```bash
python3 rapid_reset_test.py https://target-server.com
```

### Advanced Usage

```bash
# Test with multiple connections and custom request count
python3 rapid_reset_test.py https://target-server.com \
    --connections 5 \
    --requests 200 \
    --verbose

# Test against a specific port
python3 rapid_reset_test.py https://target-server.com:8443 \
    --connections 3 \
    --requests 100

# Suppress banner output
python3 rapid_reset_test.py https://target-server.com \
    --no-banner \
    --requests 50
```

### Command Line Options

| Option | Description | Default | Range |
|--------|-------------|---------|-------|
| `url` | Target URL (required) | - | Any valid HTTP/HTTPS URL |
| `-c, --connections` | Number of concurrent connections | 1 | 1-100 |
| `-r, --requests` | Number of requests per connection | 100 | 1-10000 |
| `-v, --verbose` | Enable verbose logging | False | - |
| `--no-banner` | Suppress banner output | False | - |
| `-h, --help` | Show help message | - | - |

## 📊 Understanding Results

The tool provides detailed test results including:

- **Target URL**: The tested endpoint
- **Connections**: Number of concurrent HTTP/2 connections used
- **Requests per connection**: Number of rapid reset cycles per connection
- **Successful connections**: Connections that completed successfully
- **Total successful attacks**: Total number of rapid reset cycles completed
- **Success rate**: Percentage of successful attack cycles
- **Duration**: Total test execution time
- **Requests per second**: Attack rate achieved

### Risk Assessment

The tool automatically assesses vulnerability based on success rate:

- 🔴 **HIGH RISK** (>80% success): Server is likely vulnerable
- 🟡 **MEDIUM RISK** (50-80% success): Server may be partially vulnerable
- 🟢 **LOW RISK** (<50% success): Server appears to have mitigations

## 🔬 Technical Details

### Attack Methodology

The tool implements the Rapid Reset attack by:

1. **Establishing HTTP/2 connections** with proper TLS negotiation and ALPN
2. **Sending HTTP/2 SETTINGS frames** to configure the connection
3. **Rapidly sending HEADERS frames** to initiate new streams
4. **Immediately following with RST_STREAM frames** to cancel the streams
5. **Repeating the cycle** to overwhelm server resources

### HTTP/2 Implementation

The tool includes a custom HTTP/2 implementation featuring:

- Proper HTTP/2 connection preface handling
- SETTINGS frame negotiation and acknowledgment
- Basic HPACK header compression
- Stream multiplexing with correct stream ID management
- Frame structure compliant with RFC 7540

### Safety Features

- **Rate limiting**: Built-in limits on connections and requests
- **Authorization prompt**: Requires explicit user confirmation
- **Timeout handling**: Prevents hanging connections
- **Error handling**: Graceful failure handling and reporting

## 🛡️ Mitigation Strategies

If your server is found vulnerable, consider these mitigations:

1. **Update HTTP/2 implementations** to the latest versions
2. **Enable rate limiting** for HTTP/2 streams and connections
3. **Configure connection limits** and timeouts
4. **Implement stream reset monitoring** and blocking
5. **Use load balancers** with HTTP/2 attack protection
6. **Monitor resource usage** and implement alerting

## 📚 Examples

### Example 1: Basic Test
```bash
$ python3 rapid_reset_test.py https://example.com

╔══════════════════════════════════════════════════════════════════════╗
║                    CVE-2023-44487 Rapid Reset Tester                 ║
║                                                                      ║
║  HTTP/2 Rapid Reset Attack Testing Tool                             ║
║  WARNING: For authorized testing only!                              ║
╚══════════════════════════════════════════════════════════════════════╝

⚠️  WARNING: This tool performs a Denial of Service attack!
⚠️  Only use against systems you own or have explicit permission to test.
⚠️  Unauthorized use may be illegal and could cause service disruption.

Do you have authorization to test the target? (yes/no): yes

======================================================================
TEST RESULTS
======================================================================
Target URL:                https://example.com
Connections:              1
Requests per connection:  100
Successful connections:   1
Total successful attacks: 95
Total intended requests:  100
Success rate:             95.00%
Duration:                 2.34 seconds
Requests per second:      40.60
======================================================================

🔴 HIGH RISK: Target appears vulnerable to Rapid Reset attacks
   Consider updating HTTP/2 implementation and enabling rate limiting
```

### Example 2: Multi-Connection Test
```bash
$ python3 rapid_reset_test.py https://target.example.com \
    --connections 5 --requests 50 --verbose

# Detailed logging output shows individual connection progress
# Final results show aggregate statistics across all connections
```

## 🐛 Troubleshooting

### Common Issues

1. **Connection refused**: Target may not support HTTP/2 or HTTPS
2. **SSL/TLS errors**: Certificate issues or unsupported protocols
3. **Timeout errors**: Server may be blocking or rate limiting
4. **Permission errors**: May need elevated privileges for network operations

### Debug Steps

1. **Enable verbose logging** with `-v` flag
2. **Test with a single connection** first
3. **Verify target supports HTTP/2** using browser dev tools
4. **Check firewall and network connectivity**

## 📄 License

This tool is provided under the MIT License. See LICENSE file for details.

## 🔗 References

- [CVE-2023-44487 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487)
- [RFC 7540 - HTTP/2 Specification](https://tools.ietf.org/html/rfc7540)
- [NIST CVE Database](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)
- [Cloudflare Analysis](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)

## ⚖️ Legal Notice

This tool is intended for cybersecurity professionals, researchers, and system administrators to test their own systems or systems they have explicit permission to test. The authors are not responsible for any misuse of this tool. Always ensure you have proper authorization before conducting security tests.

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**