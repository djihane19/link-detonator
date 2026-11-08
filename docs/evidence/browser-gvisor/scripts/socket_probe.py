"""Runs inside the gVisor sandbox (same flags as a scan). Raw TCP/UDP attempts that a page
cannot make itself but a browser exploit could."""
import os, socket, struct

def dns_query(name="example.com"):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    return q

def udp_dns(server):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(dns_query(), (server, 53)); data, _ = s.recvfrom(512)
        return f"ANSWERED ({len(data)} bytes)"
    except Exception as e:
        return f"blocked ({type(e).__name__}: {e})"

def tcp(host, port):
    try:
        c = socket.create_connection((host, port), timeout=3); c.close(); return "CONNECTED"
    except Exception as e:
        return f"blocked ({type(e).__name__}: {e})"

print("kernel:", os.uname().release, "| uid:", os.getuid())
print("resolv.conf:", " ".join(l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")))
print("getaddrinfo example.com:", sorted({a[4][0] for a in socket.getaddrinfo("example.com", 443, socket.AF_INET)}))
for host, port, what in [
    ("172.30.0.1", 18080, "canary via sandbox gateway"), ("172.17.0.1", 18080, "canary via docker0"),
    ("185.92.220.83", 18080, "canary via public IP"), ("172.30.0.1", 22, "sshd via gateway"),
    ("172.30.0.1", 80, "caddy via gateway"), ("185.92.220.83", 443, "own app via public IP"),
    ("172.30.0.1", 8000, "app port via gateway"), ("169.254.169.254", 80, "cloud metadata"),
    ("10.0.0.1", 80, "10/8"), ("172.16.0.1", 80, "172.16/12"), ("192.168.0.1", 80, "192.168/16"),
    ("100.64.0.1", 80, "100.64/10 CGNAT"), ("172.30.0.2", 80, "another sandbox (ICC)"),
    ("1.1.1.1", 853, "DNS-over-TLS (port not allowed)"), ("1.1.1.1", 443, "public HTTPS (allowed, control)"),
]:
    print(f"tcp {host}:{port:<5} {what:32} {tcp(host, port)}")
for server, what in [("1.1.1.1", "pinned resolver (allowed, control)"), ("8.8.8.8", "pinned resolver (allowed, control)"),
                     ("9.9.9.9", "unauthorized resolver"), ("208.67.222.222", "unauthorized resolver"),
                     ("8.8.4.4", "unauthorized resolver"), ("172.30.0.1", "gateway resolver"), ("127.0.0.11", "docker embedded DNS")]:
    print(f"udp {server}:53 {what:36} {udp_dns(server)}")
print("tcp 9.9.9.9:53 unauthorized resolver over TCP", tcp("9.9.9.9", 53))
try:
    socket.create_connection(("fd00:ec2::254", 80), timeout=3); print("ipv6 metadata CONNECTED")
except Exception as e:
    print(f"ipv6 metadata fd00:ec2::254 blocked ({type(e).__name__}: {e})")
