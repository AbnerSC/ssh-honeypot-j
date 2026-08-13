#!/usr/bin/env python3
# Honeypot connectivity & banner probe - SAFE: only targets the user-specified honeypot.
import socket, sys

TARGET = "172.17.1.203"
PORTS = {"ssh": 2222, "telnet": 2323}
# Hard safety: refuse anything on port 22 or any other host.
assert TARGET == "172.17.1.203", "Host mismatch - abort"
for p in PORTS.values():
    assert p not in (22, 23), "Refusing to touch real SSH/Telnet port - abort"

def probe(port, timeout=6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = __import__("time").time()
        rc = s.connect_ex((TARGET, port))
        dt = __import__("time").time() - t0
        if rc != 0:
            s.close()
            return {"port": port, "reachable": False, "error": f"connect_ex rc={rc}", "dt": round(dt,3)}
        # Try to read a banner (honeypots usually send one immediately)
        banner = b""
        try:
            s.settimeout(4)
            while len(banner) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) >= 1024:
                    break
        except socket.timeout:
            pass
        s.close()
        return {"port": port, "reachable": True, "dt": round(dt,3),
                "banner": banner[:600].decode(errors="replace")}
    except Exception as e:
        return {"port": port, "reachable": False, "error": repr(e)}

for name, port in PORTS.items():
    print(f"=== {name.upper()} port {port} ===")
    r = probe(port)
    print(r)
    print()
