#!/usr/bin/env python3
"""Check whether an LG webOS TV refuses connections that look like they come from a web page.

Usage: python3 lgtest.py <TV-IP>
Uses only the Python standard library. Sends a harmless "hello" message twice:
once like an app (no Origin header) and once like the web remote (with an Origin header).
"""
import base64, json, os, socket, ssl, struct, sys


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("TV closed the connection")
        buf += chunk
    return buf


def send_text(s, text):
    data = text.encode()
    mask = os.urandom(4)
    head = bytes([0x81])
    n = len(data)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def recv_frame(s):
    b1, b2 = recv_exact(s, 2)
    op, n = b1 & 0x0F, b2 & 0x7F
    if n == 126:
        n = struct.unpack(">H", recv_exact(s, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", recv_exact(s, 8))[0]
    if b2 & 0x80:
        recv_exact(s, 4)
    return op, recv_exact(s, n)


def try_hello(host, origin):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the TV uses a self-signed certificate
    raw = socket.create_connection((host, 3001), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET / HTTP/1.1\r\nHost: {host}:3001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
    if origin:
        req += f"Origin: {origin}\r\n"
    s.sendall((req + "\r\n").encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(1024)
        if not chunk:
            return "TV closed the connection during the handshake"
        resp += chunk
    status = resp.split(b"\r\n")[0].decode(errors="replace")
    if " 101 " not in status:
        return f"TV refused the connection: {status}"
    send_text(s, json.dumps({"id": "hello", "type": "hello", "payload": {}}))
    try:
        op, payload = recv_frame(s)
    except (ConnectionError, socket.timeout, OSError) as e:
        return f"NO REPLY ({e})"
    finally:
        s.close()
    if op == 8:
        code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else None
        return f"TV hung up (close code {code}, reason {payload[2:].decode(errors='replace')!r})"
    return "OK, TV replied: " + payload.decode(errors="replace")[:200]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 lgtest.py <TV-IP>")
    host = sys.argv[1]
    for label, origin in (("Like an app (no Origin)", None),
                          ("Like the web remote (Origin: https://bekaykay.github.io)", "https://bekaykay.github.io")):
        try:
            result = try_hello(host, origin)
        except Exception as e:  # noqa: BLE001
            result = f"Could not connect: {e}"
        print(f"{label}:\n  {result}\n")
