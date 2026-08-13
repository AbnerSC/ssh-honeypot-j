#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import simulator
r = simulator.ssh_session("root", "toor", "OpenSSH_8.9p1",
                          ["uname -a", "id", "echo OK"], timeout=15)
print("SSH fixed test:", r)
assert r.get("accepted") is True, "SSH still not accepted!"
assert r.get("opened") is True
print("SSH session OK, commands echoed:", len(r.get("responses", [])))
