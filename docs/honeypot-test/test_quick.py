#!/usr/bin/env python3
# Quick single-attempt validation (SAFE: hardcoded honeypot host/ports only).
import socket, time, sys

TARGET = "172.17.1.203"
SSH_PORT = 2222
TEL_PORT = 2323
assert TARGET == "172.17.1.203"
assert SSH_PORT != 22 and TEL_PORT != 23

# ---------- Telnet minimal client ----------
def telnet_try(user, pw, timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, TEL_PORT))
    buf = b""
    def read_until(tokens, tlim=timeout):
        nonlocal buf
        end = time.time() + tlim
        while time.time() < end:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            i = 0
            out = b""
            while i < len(data):
                if data[i] == 0xFF:  # IAC
                    if i+1 < len(data):
                        cmd = data[i+1]
                        if cmd in (251,252,253,254) and i+2 < len(data):  # WILL/WONT/DO/DONT + opt
                            opt = data[i+2]
                            # refuse everything
                            resp = bytes([0xFF, 254 if cmd in (251,253) else 252, opt])
                            s.send(resp)
                            i += 3
                            continue
                        else:
                            i += 2
                            continue
                    else:
                        i += 1
                        continue
                out += bytes([data[i]])
                i += 1
            buf += out
            for tok in tokens:
                if tok in buf:
                    return True
        return False
    # wait for login prompt
    read_until(b"login:")
    s.send((user + "\r\n").encode())
    got_pw = read_until(b"assword:")
    if got_pw:
        s.send((pw + "\r\n").encode())
    read_until(b"login:", tlim=3)
    result = buf.decode(errors="replace")
    s.close()
    return {"user": user, "pw": pw, "got_password_prompt": got_pw, "tail": result[-200:]}

# ---------- SSH via paramiko ----------
def ssh_try(user, pw, timeout=10):
    import paramiko
    ok = {"host": TARGET, "port": SSH_PORT}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(TARGET, port=SSH_PORT, username=user, password=pw,
                       timeout=timeout, look_for_keys=False, allow_agent=False,
                       banner_timeout=timeout)
        ok["auth_result"] = "ACCEPTED"
        try:
            client.exec_command("echo pwned", timeout=5)
        except Exception as e:
            ok["post_auth"] = f"exec failed: {type(e).__name__}"
        client.close()
    except paramiko.AuthenticationException:
        ok["auth_result"] = "REJECTED (bad creds)"
    except paramiko.SSHException as e:
        ok["auth_result"] = f"SSHException: {e}"
    except Exception as e:
        ok["auth_result"] = f"{type(e).__name__}: {e}"
    return ok

print("TELNET test (admin:admin):")
print(telnet_try("admin", "admin"))
print()
print("SSH test (root:toor):")
print(ssh_try("root", "toor"))
