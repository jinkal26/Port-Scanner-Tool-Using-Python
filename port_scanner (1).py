import socket
import concurrent.futures
import sys
import time

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

TCP_TIMEOUT = 1.0
UDP_TIMEOUT = 2.0
MAX_WORKERS = 400

def format_port_results(results):
    """
    results: list of tuples (port, proto, service, banner_or_note, status)
    proto: 'TCP' or 'UDP'
    status: 'Open', 'Closed', 'Open|Filtered'
    """
    out = []
    out.append("Port Scan Results:")
    out.append("{:<6} {:<5} {:<15} {:<10} {}".format("Port", "Proto", "Service", "Status", "Banner/Note"))
    out.append('-' * 95)
    for port, proto, service, banner, status in sorted(results, key=lambda r: (r[0], r[1])):
        color = GREEN if status == 'Open' else (RED if status == 'Closed' else YELLOW)
        banner_display = banner.replace('\n', ' ') if banner else ''
        out.append(f"{port:<6} {proto:<5} {service:<15} {color}{status:<10}{RESET} {banner_display}")
    return "\n".join(out)

def get_banner(sock):
    # Best-effort banner read. Non-blocking approach with a short timeout.
    try:
        sock.settimeout(0.8)
        data = sock.recv(2048)
        if not data:
            return ""
        try:
            return data.decode('utf-8', errors='replace').strip()
        except Exception:
            return repr(data)
    except Exception:
        return ""

def scan_tcp(target_ip, port, timeout=TCP_TIMEOUT):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            # port is open
            try:
                service = socket.getservbyport(port, 'tcp')
            except Exception:
                service = 'Unknown'
            banner = get_banner(s)
            return (port, 'TCP', service, banner, 'Open')
        else:
            return (port, 'TCP', '', '', 'Closed')
    except Exception:
        return (port, 'TCP', '', '', 'Closed')
    finally:
        if s:
            s.close()

def scan_udp(target_ip, port, timeout=UDP_TIMEOUT):
    """
    Best-effort UDP scan:
    - Send a small UDP probe (single null byte).
    - If a response is received -> 'Open' (we have application-level response).
    - If an ICMP port unreachable is delivered, the OS usually surfaces an error (but behavior varies).
    - If no response within timeout -> 'Open|Filtered' (can't distinguish open but silent vs filtered).
    Note: Determining 'Closed' reliably requires receiving ICMP port unreachable; Python's high-level
    socket API doesn't always expose that consistently across platforms without raw sockets (root).
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # send a short probe that many services will ignore, but some (like DNS, SNMP) respond
        try:
            sock.sendto(b'\x00', (target_ip, port))
        except Exception:
            # Some errors may indicate immediate unreachable on certain platforms
            return (port, 'UDP', '', '', 'Closed')

        try:
            data, addr = sock.recvfrom(4096)
            # Got a response -> open and we have a banner/response
            try:
                banner = data.decode('utf-8', errors='replace').strip()
            except Exception:
                banner = repr(data)
            try:
                service = socket.getservbyport(port, 'udp')
            except Exception:
                service = 'Unknown'
            return (port, 'UDP', service, banner, 'Open')
        except socket.timeout:
            # No response -> open|filtered (we can't tell)
            try:
                service = socket.getservbyport(port, 'udp')
            except Exception:
                service = ''
            return (port, 'UDP', service, '', 'Open|Filtered')
        except Exception:
            # On some systems, ICMP unreachable may raise a connection reset error here
            return (port, 'UDP', '', '', 'Closed')
    finally:
        if sock:
            sock.close()

def port_scan(target_host, start_port, end_port):
    try:
        target_ip = socket.gethostbyname(target_host)
    except Exception as e:
        print(f"Error resolving host {target_host}: {e}")
        return

    print(f"Starting scan on host: {target_ip}")
    ports = list(range(start_port, end_port + 1))
    total_tasks = len(ports) * 2  # TCP + UDP per port
    results = []
    tasks_completed = 0
    start_time = time.time()

    # Use a single ThreadPoolExecutor for both TCP and UDP tasks
    workers = min(MAX_WORKERS, max(4, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_task = {}
        for p in ports:
            future = executor.submit(scan_tcp, target_ip, p)
            future_to_task[future] = ('TCP', p)
            future = executor.submit(scan_udp, target_ip, p)
            future_to_task[future] = ('UDP', p)

        try:
            for future in concurrent.futures.as_completed(future_to_task):
                res = future.result()
                if res:
                    results.append(res)
                tasks_completed += 1
                # update progress line
                sys.stdout.write(f"\rProgress: {tasks_completed}/{total_tasks} probes completed")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\nScan aborted by user.")
            executor.shutdown(wait=False, cancel_futures=True)
            return

    elapsed = time.time() - start_time
    sys.stdout.write("\n")
    print(f"Scan completed in {elapsed:.2f} seconds.\n")
    print(format_port_results(results))


if __name__ == '__main__':
    try:
        target_host = input("Enter target hostname or IP (only scan targets you are permitted to test): ").strip()
        start_port = int(input("Enter the start port: ").strip())
        end_port = int(input("Enter the end port: ").strip())
    except Exception as e:
        print(f"Invalid input: {e}")
        sys.exit(1)

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Ports must be in 1-65535 and start <= end.")
        sys.exit(1)

    port_scan(target_host, start_port, end_port)
