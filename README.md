# CVE-2023-44487 HTTP/2 Rapid Reset Testing Tool - Enhanced Edition

A comprehensive Python testing tool for **CVE-2023-44487**, the HTTP/2 Rapid Reset vulnerability. This repository contains both attack testing and verification-focused tools.

## ⚠️ **IMPORTANT DISCLAIMER**

**This tool is for educational and authorized testing purposes ONLY!**

- Only use against systems you own or have explicit written permission to test
- Unauthorized use may be illegal and could cause service disruption
- The tools perform attack tests that can impact server availability
- Always ensure you have proper authorization before testing

## 🔍 About CVE-2023-44487

CVE-2023-44487, also known as "HTTP/2 Rapid Reset," is a critical vulnerability in the HTTP/2 protocol that allows attackers to:

- Cause denial of service by rapidly sending and canceling HTTP/2 streams
- Consume excessive server resources with minimal client resources
- Bypass many traditional rate limiting mechanisms
- Affect major web servers and load balancers

**CVSS Score:** 7.5 (High)

**Impact:** Denial of Service, Resource Exhaustion

## 📋 Requirements

- Python 3.7 or higher
- `h2` library: `pip install h2`

## 📖 Installation

1. **Clone or download the repository:**
```bash
git clone https://github.com/madhusudhan-in/CVE_2023_44487-Rapid_Reset.git
cd CVE_2023_44487-Rapid_Reset
```

2. **Install dependencies:**
```bash
pip install h2
```

3. **Make scripts executable:**
```bash
chmod +x *.py
```

4. **Verify Python version:**
```bash
python3 --version  # Should be 3.7+
```

---

# 🛡️ Verification Tool (Enhanced)

## `cve_2023_44487_verifier_enhanced.py`

**Purpose:** Enforcement-signal detection for post-patch verification and compliance checking

### Key Features

- 📡 **Server SETTINGS Capture**: Logs the server's initial HTTP/2 SETTINGS frame
- 🛡️ **GOAWAY Frame Analysis**: Captures and categorizes all GOAWAY frames with RFC 9113-compliant error codes
- 📊 **Per-Second Rate Tracking**: Monitors reset rate per second to detect adaptive throttling patterns
- 🔍 **Enforcement Signal Detection**:
  - ✅ ENHANCE_YOUR_CALM (0xb) GOAWAY — protocol-layer enforcement
  - ✅ TCP RST at transport layer — edge-level intervention
  - ✅ REFUSED_STREAM (0x7) responses — stream-level rate limiting
  - ✅ Adaptive throttling patterns — intelligent rate-limiting detection
- 📈 **Connection Close Classification**: Identifies how and why connections close
- ⚡ **Concurrent Connection Testing**: Test multiple HTTP/2 connections simultaneously
- 🎯 **Intelligent Verdict System**: Classifies vulnerability status based on actual enforcement signals

### Quick Start

```bash
# Basic verification
python3 cve_2023_44487_verifier_enhanced.py target.com

# Multiple concurrent connections
python3 cve_2023_44487_verifier_enhanced.py target.com -c 5 -s 500

# Verbose output with debugging
python3 cve_2023_44487_verifier_enhanced.py target.com -v -c 3 -s 1000

# Baseline test only (normal requests)
python3 cve_2023_44487_verifier_enhanced.py target.com --baseline-only
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `host` | Target hostname (required) | - |
| `-p, --port` | Target port | 443 |
| `--no-ssl` | Disable SSL/TLS | False (SSL enabled) |
| `-s, --streams` | Number of streams per connection | 1000 |
| `-d, --delay` | Delay between stream operations (seconds) | 0.001 |
| `-c, --connections` | Number of concurrent connections | 1 |
| `--baseline-only` | Only perform baseline test (no attack) | False |
| `-v, --verbose` | Verbose/debug output | False |

### Understanding the Verdict

The script provides an intelligent verdict based on **RFC 9113-compliant** enforcement signals:

#### ✅ ENFORCEMENT CONFIRMED
```
Server sends GOAWAY with ENHANCE_YOUR_CALM (0xb) error code
Classification: NOT VULNERABLE — protocol-layer enforcement is active
Meaning: HTTP/2 implementation has proper rate-limiting controls
```

#### ⚠️ EDGE/TRANSPORT-LEVEL INTERVENTION DETECTED
```
50%+ of connections terminated via TCP reset
Classification: LIKELY PROTECTED — verify with edge/infrastructure team
Meaning: Edge appliance or DDoS protection engaged at transport layer
```

#### ⚠️ ADAPTIVE THROTTLING DETECTED
```
Per-second reset rate drops significantly over time (late buckets <60% of early)
Classification: PARTIAL PROTECTION — confirm with infrastructure team
Meaning: Server or edge slowing the attack adaptively
```

#### ⚠️ STREAM REFUSAL DETECTED
```
Server sends REFUSED_STREAM (0x7) responses
Classification: PARTIAL PROTECTION — review rate limits
Meaning: Some stream-level rate-limiting in place
```

#### ❌ NO PROTOCOL-LAYER ENFORCEMENT OBSERVED
```
No ENHANCE_YOUR_CALM GOAWAY, no TCP resets, no throttling detected
Classification: VECTOR EXERCISABLE — exploitability unconfirmed
Important: This doesn't prove DoS exploitability. Edge volumetric/behavioral 
protections (Akamai, CloudFlare) may engage at higher scales
```

### Sample Output

```
============================================================
ENFORCEMENT SIGNAL ANALYSIS
============================================================
Server SETTINGS (initial frame):
  HEADER_TABLE_SIZE = 4096
  ENABLE_PUSH = True
  MAX_CONCURRENT_STREAMS = 128
  INITIAL_WINDOW_SIZE = 65535
  MAX_FRAME_SIZE = 16384
  → MAX_CONCURRENT_STREAMS=128 is conservative (good post-CVE default)

GOAWAY breakdown across connections:
  ENHANCE_YOUR_CALM (0xb): 3/5
  Other GOAWAY codes:      1/5
  No GOAWAY received:      1/5
  TCP reset (RST at transport): 0/5
  Total RST_STREAM frames from server: 2
  REFUSED_STREAM frames from server:   0
  Connections showing adaptive throttling: 1/5

============================================================
VERDICT
============================================================
✅ ENFORCEMENT CONFIRMED
   3/5 connection(s) received GOAWAY with ENHANCE_YOUR_CALM (0xb).
   This is the canonical signal that the CVE-2023-44487 mitigation is active.
   Classification: NOT VULNERABLE — protocol-layer enforcement is engaged.
```

### Advanced Usage Examples

#### 1. Post-Patch Verification
```bash
# Verify patch deployment with 10 connections, 500 streams each
python3 cve_2023_44487_verifier_enhanced.py prod-api.example.com \
    -c 10 \
    -s 500 \
    -d 0.0001 \
    -v
```

#### 2. Custom Port and Protocol
```bash
# Test non-standard HTTPS port
python3 cve_2023_44487_verifier_enhanced.py example.com \
    -p 8443 \
    -c 5 \
    -s 1000
```

#### 3. Infrastructure Compliance Check
```bash
# Minimal load compliance test
python3 cve_2023_44487_verifier_enhanced.py example.com \
    -c 3 \
    -s 200 \
    --baseline-only
```

### Technical Details

#### HTTP/2 Enforcement Signals

**ENHANCE_YOUR_CALM (Error Code 0xb):**
- Canonical HTTP/2 rate-limiting signal (RFC 9113)
- Server responds to rapid reset attack with GOAWAY 0xb
- Indicates protocol-layer defense is active
- Best practice post-CVE-2023-44487 mitigation

**REFUSED_STREAM (Error Code 0x7):**
- Server refuses to open new streams
- Alternative stream-level rate-limiting mechanism
- Less common but still valid defense

**Per-Second Reset Rate Analysis:**
- Buckets stream resets into 1-second windows
- Detects adaptive throttling: if late buckets <<early buckets, server is adapting
- Suggests intelligent rate-limiting (not just hard limits)

**TCP RST at Transport Layer:**
- Connection terminated at TCP layer before graceful HTTP/2 close
- Suggests edge appliance or firewall intervention
- Not HTTP/2 protocol-layer enforcement, but effective

#### Connection Close Classifications

| Close Cause | Meaning |
|-------------|---------|
| `goaway_enhance_your_calm` | GOAWAY 0xb received (best indicator of CVE fix) |
| `goaway_*` | GOAWAY with other error code |
| `tcp_reset` | TCP RST received (edge-level intervention) |
| `broken_pipe` / `recv_error` | Connection error during communication |
| `eof_no_goaway` | Unexpected EOF without GOAWAY |
| `no_close_no_enforcement` | Connection stayed open (no enforcement detected) |

### Integration Examples

#### Python Automation
```python
import asyncio
import subprocess

def run_verification(target: str, num_connections: int = 3):
    cmd = [
        'python3', 'cve_2023_44487_verifier_enhanced.py',
        target,
        '-c', str(num_connections),
        '-s', '500',
        '-v'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Parse verdict from output
    if "ENFORCEMENT CONFIRMED" in result.stdout:
        print(f"✅ {target} is protected")
        return "protected"
    elif "LIKELY PROTECTED" in result.stdout:
        print(f"⚠️  {target} has edge-level protection")
        return "edge_protected"
    else:
        print(f"❌ {target} shows no enforcement")
        return "vulnerable"

# Run test
status = run_verification("example.com", 5)
```

#### Continuous Monitoring
```bash
#!/bin/bash
# Monitor critical services weekly

TARGETS="api.example.com web.example.com cdn.example.com"
LOG_DIR="/var/log/cve-2023-44487"
mkdir -p "$LOG_DIR"

for target in $TARGETS; do
    python3 cve_2023_44487_verifier_enhanced.py "$target" \
        -c 3 \
        -s 500 \
        -v > "$LOG_DIR/$target-$(date +%Y%m%d).log" 2>&1
done
```

---

# 🚀 Attack Testing Tool (Legacy)

## `rapid_reset_test.py`

**Purpose:** Comprehensive HTTP/2 Rapid Reset attack testing with multiple patterns

### Features

- ⚡ **Rapid Reset**: Standard HEADERS + immediate RST_STREAM
- 💥 **Burst Reset**: Requests in bursts with configurable delays
- 📈 **Gradual Reset**: Gradually increasing attack rate
- 🎲 **Random Reset**: Random timing to bypass predictive filtering
- 🌊 **Continuation Flood**: CONTINUATION frame flood attack
- 🔀 **Mixed Pattern**: Combination of multiple patterns

### Basic Usage

```bash
python3 rapid_reset_test.py https://target-server.com
```

### Advanced Usage Examples

#### High-Throughput Load Testing
```bash
python3 rapid_reset_test.py https://target.com \
    --connections 50 \
    --requests 1000 \
    --delay 0 \
    --pattern rapid_reset \
    --track-latency \
    --output json
```

#### Stealth Testing with Custom Headers
```bash
python3 rapid_reset_test.py https://target.com \
    --pattern burst_reset \
    --burst-size 5 \
    --burst-delay 2.0 \
    --custom-headers "User-Agent: Mozilla/5.0" \
    --jitter 0.3
```

#### Protocol-Specific Testing
```bash
python3 rapid_reset_test.py https://target.com \
    --window-size 32768 \
    --frame-size 32768 \
    --header-table-size 8192 \
    --enable-push \
    --priority-frames \
    --randomize-streams
```

### Command Line Options

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

### Risk Assessment

The tool automatically assesses vulnerability:

- 🔴 **HIGH RISK** (>80% success): Server likely vulnerable
- 🟡 **MEDIUM RISK** (50-80% success): Partial vulnerability
- 🟢 **LOW RISK** (<50% success): Mitigations appear effective

---

## 🐛 Troubleshooting

### Common Issues

1. **"No module named 'h2'"**
   ```bash
   pip install h2
   ```

2. **Connection refused / timeout**
   - Verify target supports HTTP/2: `curl -I --http2 https://target.com`
   - Check firewall rules
   - Verify SSL/TLS certificate is valid

3. **ImportError with h2 modules**
   ```bash
   pip install --upgrade h2
   python3 --version  # Must be 3.7+
   ```

4. **Permission denied**
   ```bash
   chmod +x *.py
   python3 cve_2023_44487_verifier_enhanced.py target.com
   ```

### Debug Steps

1. **Enable verbose logging:**
   ```bash
   python3 cve_2023_44487_verifier_enhanced.py target.com -v
   ```

2. **Test with minimal parameters:**
   ```bash
   python3 cve_2023_44487_verifier_enhanced.py target.com -s 10 -c 1
   ```

3. **Verify HTTP/2 support:**
   ```bash
   python3 -c "import h2; print('h2 library OK')"
   ```

---

## 📚 References

- [CVE-2023-44487 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487)
- [RFC 9113 - HTTP/2 Specification](https://tools.ietf.org/html/rfc9113)
- [NIST CVE Database](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)
- [Cloudflare Technical Analysis](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)
- [Google Security Blog](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack)

---

## ⚖️ Legal Notice

This repository is intended for cybersecurity professionals, researchers, and system administrators to test their own systems or systems they have explicit permission to test.

**Key Legal Points:**
- Only test systems you own or have written permission to test
- Unauthorized testing may violate computer crime laws
- These tools can cause real service disruption
- Always inform relevant stakeholders before testing
- Use during maintenance windows when possible
- Document all testing activities for audit purposes
- The authors are not responsible for unauthorized use

**Remember: With great power comes great responsibility. Use these tools ethically and legally.**

---

## 📄 License

This tool is provided under the MIT License. See LICENSE file for details.

## 🆕 What's New

### Enhanced Verification Tool
- ✅ **Server SETTINGS Capture**: Examine defensive HTTP/2 parameters
- ✅ **GOAWAY Frame Analysis**: RFC 9113-compliant error code classification
- ✅ **Adaptive Throttling Detection**: Identify rate-limiting patterns
- ✅ **Intelligent Verdict System**: Clear classifications (enforcement confirmed, edge protected, vulnerable, etc.)
- ✅ **Connection Close Classification**: Understand how/why connections terminate
- ✅ **Concurrent Connection Testing**: Multiple simultaneous tests for reliability

### Tool Selection Guide

| Use Case | Tool | Reason |
|----------|------|--------|
| Post-patch verification | `cve_2023_44487_verifier_enhanced.py` | Detects enforcement signals |
| Compliance checking | `cve_2023_44487_verifier_enhanced.py` | Validates CVE mitigation |
| Infrastructure assessment | `cve_2023_44487_verifier_enhanced.py` | Clear, actionable verdicts |
| Attack research | `rapid_reset_test.py` | Multiple attack patterns |
| Performance testing | `rapid_reset_test.py` | Comprehensive metrics |
| Custom patterns | `rapid_reset_test.py` | Granular configuration |
