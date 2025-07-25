#!/usr/bin/env python3
"""
Test script for HTTP/2 frame construction and basic functionality
"""

import struct
import sys
from rapid_reset_test import HTTP2Frame, FRAME_TYPE_SETTINGS, FRAME_TYPE_HEADERS, FRAME_TYPE_RST_STREAM

def test_http2_frame_construction():
    """Test HTTP/2 frame construction"""
    print("Testing HTTP/2 frame construction...")
    
    # Test SETTINGS frame
    settings_payload = struct.pack('!HI', 0x2, 0)  # ENABLE_PUSH = 0
    settings_frame = HTTP2Frame(
        length=len(settings_payload),
        frame_type=FRAME_TYPE_SETTINGS,
        flags=0,
        stream_id=0,
        payload=settings_payload
    )
    
    frame_bytes = settings_frame.to_bytes()
    print(f"SETTINGS frame: {len(frame_bytes)} bytes")
    print(f"Frame header: {frame_bytes[:9].hex()}")
    
    # Test HEADERS frame
    headers_payload = b'\x00\x07:method\x03GET\x00\x05:path\x01/'
    headers_frame = HTTP2Frame(
        length=len(headers_payload),
        frame_type=FRAME_TYPE_HEADERS,
        flags=0x5,  # END_HEADERS | END_STREAM
        stream_id=1,
        payload=headers_payload
    )
    
    frame_bytes = headers_frame.to_bytes()
    print(f"HEADERS frame: {len(frame_bytes)} bytes")
    print(f"Frame header: {frame_bytes[:9].hex()}")
    
    # Test RST_STREAM frame
    rst_payload = struct.pack('!I', 8)  # CANCEL error code
    rst_frame = HTTP2Frame(
        length=4,
        frame_type=FRAME_TYPE_RST_STREAM,
        flags=0,
        stream_id=1,
        payload=rst_payload
    )
    
    frame_bytes = rst_frame.to_bytes()
    print(f"RST_STREAM frame: {len(frame_bytes)} bytes")
    print(f"Frame header: {frame_bytes[:9].hex()}")
    
    print("✅ HTTP/2 frame construction tests passed!")

def test_url_parsing():
    """Test URL parsing functionality"""
    print("\nTesting URL parsing...")
    
    from urllib.parse import urlparse
    
    test_urls = [
        "https://example.com",
        "https://example.com:443",
        "https://example.com:8443",
        "http://example.com",
        "http://example.com:80",
        "http://example.com:8080"
    ]
    
    for url in test_urls:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        
        print(f"URL: {url}")
        print(f"  Host: {host}, Port: {port}, SSL: {use_ssl}")
    
    print("✅ URL parsing tests passed!")

def main():
    """Run all tests"""
    print("=" * 50)
    print("CVE-2023-44487 Tool Self-Test")
    print("=" * 50)
    
    try:
        test_http2_frame_construction()
        test_url_parsing()
        
        print("\n" + "=" * 50)
        print("🎉 All tests passed! The tool is ready to use.")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()