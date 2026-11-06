"""Probes that verify_sandbox.sh runs inside a throwaway sandbox container.

The sandbox policy forbids mounts and stdin, so the script passes this file's text as
`python -c` and reads results from stdout. Standard library only.

Output is one line per result: PASS or FAIL, check name, detail, separated by tabs.
A check that crashes reports FAIL; it must never look like a pass.
"""

import errno
import os
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time

CONNECT_TIMEOUT_S = 5.0
FORK_CEILING = 400
ALLOC_STEP = 32 * 1024 * 1024
ALLOC_CEILING = 2048 * 1024 * 1024
PAGE = 4096
EXPECTED_PIDS_MAX = "256"
EXPECTED_MEMORY_MAX = str(1024 * 1024 * 1024)
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|^LD_(?!LIBRARY_PATH$|PRELOAD$)", re.IGNORECASE)
PUBLIC_V6_TARGET = "2001:4860:4860::8888"
CONNECTION_CAP_ATTEMPTS = 48


def emit(ok: bool, check: str, detail: str) -> None:
    clean = detail.replace("\t", " ").replace("\n", " ")
    print(f"{'PASS' if ok else 'FAIL'}\t{check}\t{clean}", flush=True)


def tcp_outcome(host: str, port: int, family: int = socket.AF_INET) -> str:
    """Returns "connected", or the name of the error that stopped the connection."""
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(CONNECT_TIMEOUT_S)
        try:
            sock.connect((host, port))
            return "connected"
        except TimeoutError:
            return "timeout"
        except OSError as exc:
            return errno.errorcode.get(exc.errno or 0, str(exc))


def expect_blocked(check: str, host: str, port: int) -> None:
    outcome = tcp_outcome(host, port)
    emit(outcome != "connected", check, f"{host}:{port} -> {outcome}")


def probe_network(public_ip: str, gateway: str, resolver: str, other_resolver: str, name: str) -> None:
    expect_blocked("metadata blocked", "169.254.169.254", 80)
    for host in ("10.0.0.1", "172.16.0.1", "192.168.0.1"):
        expect_blocked("RFC1918 blocked", host, 80)
    expect_blocked("CGNAT blocked", "100.64.0.1", 80)
    for port in (22, 80, 443, 8000):
        expect_blocked("host gateway blocked", gateway, port)
    for port in (22, 80, 443, 8000):
        expect_blocked("public-IP blocked", public_ip, port)
    expect_blocked("other ports blocked", resolver, 22)
    probe_other_resolver(other_resolver)
    probe_ipv6()
    probe_dns(name)
    probe_https(name)
    probe_connection_cap(name)


def probe_other_resolver(host: str) -> None:
    query = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(CONNECT_TIMEOUT_S)
        try:
            sock.connect((host, 53))
            sock.send(query)
            sock.recv(512)
            emit(False, "unpinned DNS blocked", f"{host}:53 answered")
        except OSError as exc:
            emit(True, "unpinned DNS blocked", f"{host}:53 -> {type(exc).__name__}")


def probe_ipv6() -> None:
    try:
        outcome = tcp_outcome(PUBLIC_V6_TARGET, 443, socket.AF_INET6)
    except OSError as exc:
        outcome = type(exc).__name__
    emit(outcome != "connected", "IPv6 egress blocked", outcome)


def probe_dns(name: str) -> None:
    try:
        answers = {info[4][0] for info in socket.getaddrinfo(name, 443, socket.AF_INET)}
        emit(bool(answers), "DNS works", f"{name} -> {len(answers)} address(es)")
    except OSError as exc:
        emit(False, "DNS works", f"{name} -> {exc}")


def probe_https(name: str) -> None:
    # This tests reachability, not the certificate store, so verification is off.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((name, 443), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=name) as tls:
                tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                status = tls.recv(64).split(b"\r\n", 1)[0].decode("ascii", "replace")
        emit(status.startswith("HTTP/"), "public HTTPS allowed", f"{name}: {status}")
    except OSError as exc:
        emit(False, "public HTTPS allowed", f"{name}: {exc}")


def probe_connection_cap(name: str) -> None:
    """Holds connections open to one host until the firewall's per-destination cap refuses one."""
    address = socket.getaddrinfo(name, 443, socket.AF_INET)[0][4][0]
    held: list[socket.socket] = []
    outcome = "no refusal"
    try:
        for _ in range(CONNECTION_CAP_ATTEMPTS):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT_S)
            held.append(sock)
            try:
                sock.connect((address, 443))
            except OSError as exc:
                outcome = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
                break
    finally:
        count = len(held)
        for sock in held:
            sock.close()
    emit(outcome == "EHOSTUNREACH", "connection cap per destination", f"attempt {count} -> {outcome}")


def probe_filesystem() -> None:
    probe_rootfs()
    probe_tmp()


def probe_rootfs() -> None:
    read_only = bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    try:
        with open("/ld-rootfs-probe", "w"):
            pass
        os.unlink("/ld-rootfs-probe")
        write = "write succeeded"
    except OSError as exc:
        write = errno.errorcode.get(exc.errno or 0, str(exc))
    emit(read_only and write == "EROFS", "rootfs read-only", f"mounted ro={read_only}, write -> {write}")


def probe_tmp() -> None:
    path = f"/tmp/ld-noexec-probe-{os.getpid()}"
    try:
        with open(path, "w") as script:
            script.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, stat.S_IRWXU)
        subprocess.run([path], check=False)
        outcome = "executed"
    except PermissionError:
        outcome = "refused"
    except OSError as exc:
        outcome = f"error: {exc}"
    finally:
        if os.path.exists(path):
            os.unlink(path)
    emit(outcome == "refused", "/tmp noexec", f"exec -> {outcome}")


def probe_identity() -> None:
    fields: dict[str, str] = {}
    with open("/proc/self/status") as status:
        for line in status:
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    caps = {key: fields.get(key, "absent") for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    no_caps = all(value != "absent" and int(value, 16) == 0 for value in caps.values())
    nnp = fields.get("NoNewPrivs") == "1"
    emit(no_caps and nnp, "no capabilities", f"CapBnd={caps['CapBnd']} CapEff={caps['CapEff']} NoNewPrivs={nnp}")

    uid, gid = os.getuid(), os.getgid()
    emit(uid != 0 and os.geteuid() != 0 and gid != 0, "non-root", f"uid={uid} gid={gid}")

    # Names only: this output is logged, so values must never appear in it.
    suspicious = sorted(name for name in os.environ if SECRET_NAME.search(name))
    emit(not suspicious, "no env secrets", f"secret-like variable names: {suspicious or 'none'}")


def read_first(*paths: str) -> str:
    for path in paths:
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            continue
    return "unreadable"


def probe_pids(ceiling: int = FORK_CEILING) -> None:
    limit = read_first("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max")
    children: list[int] = []
    refused = False
    try:
        for _ in range(ceiling):
            pid = os.fork()
            if pid == 0:
                time.sleep(60)
                os._exit(0)
            children.append(pid)
    except OSError as exc:
        refused = exc.errno == errno.EAGAIN
    finally:
        for pid in children:
            os.kill(pid, signal.SIGKILL)
        for pid in children:
            os.waitpid(pid, 0)
    outcome = f"refused after {len(children)} forks" if refused else f"not refused in {len(children)} forks"
    emit(refused and limit == EXPECTED_PIDS_MAX, "pid limit", f"pids.max={limit}, {outcome}")


def allocate_until_killed(progress_fd: int) -> None:
    blocks = []
    for _ in range(ALLOC_CEILING // ALLOC_STEP):
        block = bytearray(ALLOC_STEP)
        # A fresh bytearray may be untouched zero pages; writing makes them count.
        block[::PAGE] = b"\x01" * len(range(0, ALLOC_STEP, PAGE))
        blocks.append(block)
        os.write(progress_fd, b".")


def probe_memory() -> None:
    limit = read_first("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes")
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        allocate_until_killed(write_fd)
        os._exit(0)
    os.close(write_fd)
    steps = 0
    while chunk := os.read(read_fd, 4096):
        steps += len(chunk)
    os.close(read_fd)
    _, wait_status = os.waitpid(pid, 0)
    killed = os.WIFSIGNALED(wait_status) and os.WTERMSIG(wait_status) == signal.SIGKILL
    reached_mib = steps * ALLOC_STEP // (1024 * 1024)
    emit(killed and limit == EXPECTED_MEMORY_MAX, "memory limit",
         f"memory.max={limit}, allocator killed={killed} after {reached_mib} MiB")


COMMANDS = {
    "network": probe_network,
    "filesystem": probe_filesystem,
    "identity": probe_identity,
    "pids": lambda *args: probe_pids(*(int(arg) for arg in args)),
    "memory": probe_memory,
}


def main(argv: list[str]) -> int:
    command, *args = argv
    try:
        COMMANDS[command](*args)
    except Exception as exc:  # any crash has to surface as a FAIL line
        emit(False, f"probe {command}", f"crashed: {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
