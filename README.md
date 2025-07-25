# CVE-2023-44487 HTTP/2 Rapid Reset Testing Tool - Enhanced Edition

A comprehensive Python testing tool for **CVE-2023-44487**, the HTTP/2 Rapid Reset vulnerability. This enhanced version provides granular control over testing parameters, multiple attack patterns, and advanced monitoring capabilities.

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

## 🚀 Enhanced Features

### **Multiple Attack Patterns**
- ⚡ **Rapid Reset**: Standard HEADERS + immediate RST_STREAM
- 💥 **Burst Reset**: Requests in bursts with configurable delays
- 📈 **Gradual Reset**: Gradually increasing attack rate
- 🎲 **Random Reset**: Random timing to bypass predictive filtering
- 🌊 **Continuation Flood**: CONTINUATION frame flood attack
- 🔀 **Mixed Pattern**: Combination of multiple patterns

### **Granular Configuration**
- 📡 **Connection Controls**: Timeouts, delays, concurrent limits
- ⏱️ **Timing Controls**: Precise timing with jitter support
- 🌐 **HTTP/2 Protocol**: Window sizes, frame sizes, HPACK settings
- 📋 **Header Customization**: Custom headers, random generation
- 🔬 **Advanced Options**: Stream ID randomization, priority frames
- 📊 **Monitoring**: Latency tracking, traffic analysis, error monitoring

### **Output Formats**
- 🖥️ **Console**: Human-readable with progress updates
- 📋 **JSON**: Machine-readable structured data
- 📊 **CSV**: Spreadsheet-compatible for analysis
- 🗃️ **XML**: Enterprise tool integration

### **Safety Features**
- 🛡️ **Authorization Controls**: Mandatory confirmation prompts
- 🔒 **Rate Limiting**: Built-in connection and request limits
- 🎛️ **Error Handling**: Graceful failure handling
- 📝 **Audit Trail**: Comprehensive logging capabilities

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (uses only Python standard library)

## 📖 Installation

1. **Clone or download the script:**
```bash
git clone https://github.com/madhusudhan-in/CVE_2023_44487-Rapid_Reset.git
cd CVE_2023_44487-Rapid_Reset
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

### Advanced Usage Examples

#### 1. High-Throughput Load Testing
```bash
python3 rapid_reset_test.py https://target.com \
    --connections 50 \
    --requests 1000 \
    --delay 0 \
    --pattern rapid_reset \
    --track-latency \
    --output json
```

#### 2. Stealth Testing with Custom Headers
```bash
python3 rapid_reset_test.py https://target.com \
    --pattern burst_reset \
    --burst-size 5 \
    --burst-delay 2.0 \
    --custom-headers "User-Agent: Mozilla/5.0 (legitbot)" "Authorization: Bearer token123" \
    --jitter 0.3
```

#### 3. Protocol-Specific Testing
```bash
python3 rapid_reset_test.py https://target.com \
    --window-size 32768 \
    --frame-size 32768 \
    --header-table-size 8192 \
    --enable-push \
    --priority-frames \
    --randomize-streams
```

#### 4. Comprehensive Monitoring Test
```bash
python3 rapid_reset_test.py https://target.com \
    --connections 10 \
    --requests 200 \
    --pattern mixed_pattern \
    --track-latency \
    --track-responses \
    --monitor-memory \
    --verbose \
    --debug \
    --log-file attack.log
```

#### 5. CONTINUATION Flood Attack
```bash
python3 rapid_reset_test.py https://target.com \
    --pattern continuation_flood \
    --requests 50 \
    --random-headers \
    --header-count 20
```

### Complete Command Line Options

#### Connection Settings
| Option | Description | Default |
|--------|-------------|---------|
| `-c, --connections N` | Number of concurrent connections | 1 |
| `--connection-timeout SEC` | Connection timeout in seconds | 10 |
| `--read-timeout SEC` | Read timeout for responses | 5 |
| `--connection-delay SEC` | Delay between connections | 0.0 |

#### Request Settings
| Option | Description | Default |
|--------|-------------|---------|
| `-r, --requests N` | Requests per connection | 100 |
| `--delay SEC` | Delay between HEADERS and RST_STREAM | 0.001 |
| `--request-delay SEC` | Delay between requests | 0.0 |
| `--jitter FACTOR` | Timing randomization factor | 0.0 |

#### Attack Patterns
| Option | Description | Default |
|--------|-------------|---------|
| `--pattern TYPE` | Attack pattern to use | rapid_reset |
| `--burst-size N` | Requests per burst | 10 |
| `--burst-delay SEC` | Delay between bursts | 0.1 |

**Available Patterns:**
- `rapid_reset` - Standard rapid reset attack
- `burst_reset` - Burst-based attacks
- `gradual_reset` - Gradually increasing rate
- `random_reset` - Random timing
- `continuation_flood` - CONTINUATION frame flood
- `mixed_pattern` - Mix of patterns

#### HTTP/2 Protocol Settings
| Option | Description | Default |
|--------|-------------|---------|
| `--window-size BYTES` | HTTP/2 initial window size | 65535 |
| `--frame-size BYTES` | Maximum frame size | 16384 |
| `--header-table-size BYTES` | HPACK header table size | 4096 |
| `--enable-push` | Enable HTTP/2 server push | False |
| `--rst-error-code CODE` | RST_STREAM error code | 8 |

#### Header Customization
| Option | Description | Default |
|--------|-------------|---------|
| `--custom-headers HEADER` | Custom headers (Name: Value) | None |
| `--random-headers` | Generate random headers | False |
| `--header-count N` | Number of random headers | 5 |

#### Advanced Options
| Option | Description | Default |
|--------|-------------|---------|
| `--randomize-streams` | Use random stream IDs | False |
| `--priority-frames` | Include priority information | False |
| `--continue-on-error` | Continue after errors | True |
| `--max-errors N` | Maximum errors before stopping | 10 |

#### Monitoring Options
| Option | Description | Default |
|--------|-------------|---------|
| `--track-latency` | Track request latency | False |
| `--track-responses` | Track server responses | False |
| `--monitor-memory` | Monitor memory usage | False |

#### Output Options
| Option | Description | Default |
|--------|-------------|---------|
| `--output FORMAT` | Output format | console |
| `--output-file FILE` | Output filename | auto-generated |
| `--verbose, -v` | Verbose output | False |
| `--debug` | Debug logging | False |
| `--log-file FILE` | Log to file | None |

**Available Output Formats:**
- `console` - Human-readable console output
- `json` - Machine-readable JSON
- `csv` - Spreadsheet-compatible CSV
- `xml` - Structured XML format

## 📊 Understanding Results

### Enhanced Result Format

The tool provides comprehensive results including:

- **Attack Configuration**: Complete test parameters
- **Connection Statistics**: Per-connection success/failure rates
- **Traffic Analysis**: Bytes sent/received, request rates
- **Latency Metrics**: Request timing analysis (if enabled)
- **Error Analysis**: Detailed error tracking and categorization
- **Risk Assessment**: Automated vulnerability scoring

### Sample JSON Output Structure

```json
{
  "target_url": "https://example.com",
  "test_config": {
    "attack_pattern": "rapid_reset",
    "max_connections": 10,
    "requests_per_connection": 100,
    "delay_between_headers_rst": 0.001
  },
  "test_summary": {
    "duration": 2.34,
    "successful_connections": 10,
    "total_successful_attacks": 950,
    "success_rate": 95.0,
    "requests_per_second": 405.98,
    "total_bytes_sent": 125600,
    "average_latency": 0.0024
  },
  "connection_stats": [...],
  "errors": [...],
  "timestamp": 1640995200.0
}
```

### Risk Assessment

The tool automatically assesses vulnerability:

- 🔴 **HIGH RISK** (>80% success): Server likely vulnerable
- 🟡 **MEDIUM RISK** (50-80% success): Partial vulnerability
- 🟢 **LOW RISK** (<50% success): Mitigations appear effective

## 🔬 Technical Details

### Attack Methodologies

1. **Rapid Reset**: Sends HEADERS immediately followed by RST_STREAM
2. **Burst Reset**: Groups requests into bursts with configurable delays
3. **Gradual Reset**: Progressively increases attack intensity
4. **Random Reset**: Uses unpredictable timing patterns
5. **Continuation Flood**: Exploits CONTINUATION frame processing
6. **Mixed Pattern**: Combines multiple techniques

### HTTP/2 Implementation

- Proper HTTP/2 connection preface handling
- SETTINGS frame negotiation with custom parameters
- Advanced HPACK header compression options
- Stream multiplexing with configurable stream IDs
- Frame structure compliant with RFC 7540
- Support for HTTP/2 extensions and priority frames

### Monitoring Capabilities

- **Latency Tracking**: Microsecond-precision timing
- **Traffic Analysis**: Comprehensive byte-level monitoring
- **Error Classification**: Detailed error categorization
- **Performance Metrics**: Request rates and throughput analysis
- **Protocol Debugging**: Frame-level inspection capabilities

## 🛡️ Mitigation Strategies

If your server is found vulnerable, implement these mitigations:

### Immediate Actions
1. **Update HTTP/2 implementations** to the latest versions
2. **Enable rate limiting** for HTTP/2 streams and connections
3. **Configure connection limits** and request timeouts
4. **Implement stream reset monitoring** and blocking

### Advanced Protections
1. **Deploy HTTP/2-aware load balancers** with attack protection
2. **Configure adaptive rate limiting** based on connection patterns
3. **Implement request prioritization** and resource allocation limits
4. **Monitor server resources** and implement alerting
5. **Use connection coalescing** and multiplexing controls

### Monitoring and Detection
1. **Monitor RST_STREAM rates** and patterns
2. **Track connection establishment rates**
3. **Implement anomaly detection** for HTTP/2 traffic
4. **Log and analyze** attack patterns for future protection

## 🔗 Integration Examples

### Python Automation
```python
import subprocess
import json

# Run automated test
result = subprocess.run([
    'python3', 'rapid_reset_test.py',
    'https://target.com',
    '--pattern', 'mixed_pattern',
    '--output', 'json',
    '--output-file', 'results.json'
])

# Analyze results
with open('results.json') as f:
    data = json.load(f)
    vulnerability_score = data['test_summary']['success_rate']
    if vulnerability_score > 80:
        print(f"HIGH RISK: {vulnerability_score}% success rate")
```

### Continuous Monitoring
```bash
#!/bin/bash
# Cron job: 0 2 * * * /path/to/monitor.sh

python3 rapid_reset_test.py https://myserver.com \
    --pattern rapid_reset \
    --connections 5 \
    --requests 50 \
    --output json \
    --output-file /var/log/rapid-reset-$(date +%Y%m%d).json

# Alert if vulnerability detected
if [ $(jq '.test_summary.success_rate' /var/log/rapid-reset-$(date +%Y%m%d).json) -gt 80 ]; then
    echo "ALERT: Server vulnerable to rapid reset attack" | mail -s "Security Alert" admin@example.com
fi
```

### Data Analysis
```python
import pandas as pd
import matplotlib.pyplot as plt

# Load and analyze CSV results
df = pd.read_csv('results.csv')

# Visualize attack success by connection
plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
df.plot(x='connection_id', y='successful_attacks', kind='bar')
plt.title('Attack Success by Connection')

plt.subplot(1, 2, 2)
df['success_rate'] = (df['successful_attacks'] / df['total_attacks']) * 100
plt.hist(df['success_rate'], bins=20)
plt.title('Success Rate Distribution')
plt.show()
```

## 🐛 Troubleshooting

### Common Issues

1. **Connection refused**: 
   - Verify target supports HTTP/2
   - Check firewall and network connectivity
   - Ensure HTTPS is properly configured

2. **SSL/TLS errors**: 
   - Certificate validation issues
   - Use `--debug` for detailed SSL information
   - Check ALPN negotiation

3. **Low success rates**:
   - Server may have rate limiting enabled
   - Try different attack patterns
   - Adjust timing parameters

4. **Performance issues**:
   - Reduce connection count for testing
   - Use `--debug` and `--log-file` for analysis
   - Monitor system resources

### Debug Steps

1. **Enable verbose logging**: `--verbose --debug --log-file debug.log`
2. **Test with minimal load**: `--connections 1 --requests 10`
3. **Verify HTTP/2 support**: Use browser dev tools
4. **Check server responses**: `--track-responses`
5. **Monitor latency**: `--track-latency`

## 📄 License

This tool is provided under the MIT License. See LICENSE file for details.

## 🔗 References

- [CVE-2023-44487 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487)
- [RFC 7540 - HTTP/2 Specification](https://tools.ietf.org/html/rfc7540)
- [NIST CVE Database](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)
- [Cloudflare Technical Analysis](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)
- [Google Security Blog](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack)

## ⚖️ Legal Notice

This tool is intended for cybersecurity professionals, researchers, and system administrators to test their own systems or systems they have explicit permission to test. The authors are not responsible for any misuse of this tool.

**Key Legal Points:**
- Only test systems you own or have written permission to test
- Unauthorized testing may violate computer crime laws
- This tool can cause real service disruption
- Always inform relevant stakeholders before testing
- Use during maintenance windows when possible
- Document all testing activities for audit purposes

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**

## 🆕 What's New in Enhanced Version

### Version 2.0 Features
- ✅ **6 Attack Patterns**: Multiple sophisticated attack vectors
- ✅ **40+ Configuration Options**: Granular control over all parameters
- ✅ **4 Output Formats**: Console, JSON, CSV, XML support
- ✅ **Advanced Monitoring**: Latency tracking, traffic analysis, error monitoring
- ✅ **Protocol Customization**: HTTP/2 window sizes, frame sizes, HPACK settings
- ✅ **Header Manipulation**: Custom headers, random generation, CONTINUATION floods
- ✅ **Timing Controls**: Jitter support, burst patterns, gradual escalation
- ✅ **Safety Enhancements**: Better rate limiting, error handling, audit trails
- ✅ **Integration Ready**: JSON/CSV output for automation and analysis

### Migration from Basic Version
The enhanced version maintains backward compatibility with the basic version. All existing command-line options continue to work, with new options providing additional capabilities.

For users upgrading from the basic version:
```bash
# Old basic usage still works
python3 rapid_reset_test.py https://example.com --connections 5 --requests 100

# New enhanced usage with additional options
python3 rapid_reset_test.py https://example.com \
    --connections 5 --requests 100 \
    --pattern burst_reset --track-latency --output json
```