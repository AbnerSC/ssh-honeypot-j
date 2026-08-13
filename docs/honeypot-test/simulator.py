#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-attacker honeypot simulation  (SAFE / AUTHORIZED TEST OF OWN HONEYPOT)
Targets ONLY:
    host 172.17.1.203  SSH port 2222   Telnet port 2323
NEVER port 22, NEVER port 23, NEVER any other host. Hard guards below.
Spawns >=20 concurrent attacker profiles that hammer the honeypot for >=10 min,
issuing benign recon commands to exercise credential + command capture.
All traffic originates from THIS host's real IP; "source_ip" fields below are
SIMULATION LABELS only (clearly marked) used to attribute attackers logically.
"""
import socket, threading, time, json, random, string, sys, os

# ---------------- HARD SAFETY GUARD ----------------
TARGET = "172.17.1.203"
SSH_PORT = 2222
TEL_PORT = 2323
if TARGET != "172.17.1.203":
    sys.exit("ABORT: host guard")
if SSH_PORT == 22 or TEL_PORT == 23:
    sys.exit("ABORT: refusing real SSH/Telnet port")
import paramiko  # available to session functions (used after the guard)

DURATION = 660          # 11 minutes (>= 10)
NUM_ATTACKERS = 24      # >= 20
OUTDIR = os.path.dirname(os.path.abspath(__file__))

# ---------------- shared data ----------------
STOP = threading.Event()
LOG_LOCK = threading.Lock()
ATTEMPTS = []           # list of dicts
START_TS = time.time()

# Common botnet-style credential pairs (standard weak/default lists, benign)
CRED_POOL = [
    ("root","toor"),("root","root"),("root","password"),("root","123456"),
    ("admin","admin"),("admin","password"),("admin","123456"),
    ("administrator","P@ssw0rd"),("administrator","admin"),
    ("guest","guest"),("guest","123456"),("test","test"),
    ("user","user"),("user","password"),("ubuntu","ubuntu"),
    ("oracle","oracle"),("postgres","postgres"),("mysql","mysql"),
    ("ftp","ftp"),("pi","raspberry"),("support","support"),
    ("ec2-user","ec2-user"),("centos","centos"),("deploy","deploy"),
    ("webadmin","webadmin"),("sysadmin","sysadmin"),("backup","backup"),
    ("demo","demo"),("root","admin"),("admin","1234"),
    ("root","passw0rd"),("user","letmein"),("service","service"),
    ("root","changeme"),("admin","changeme"),("test","12345"),
]

# Benign recon command arsenal (read-only; safe against an emulated shell)
CMD_POOL = [
    "uname -a","id","whoami","uptime","w","cat /etc/passwd","ls -la /",
    "ps aux","netstat -ant","crontab -l","cat /etc/shadow","ls -la /tmp",
    "df -h","free -m","cat /etc/hosts","echo PROBE_"+ "".join(random.choices(string.ascii_uppercase, k=6)),
]

# Per-attacker client banners to simulate different attacker tooling
CLIENT_BANNERS = [
    "OpenSSH_7.4", "OpenSSH_8.2p1", "OpenSSH_8.9p1", "OpenSSH_9.3",
    "libssh2_1.9.0", "PuTTY_Release_0.78", "SSH_1.99-SshLib",
    "OpenSSH_6.6.1p1", "paramiko_2.7", "AsyncSSH_2.13",
]

# Fake (label-only) source networks, clearly marked as simulation tags
FAKE_SRC_PREFIXES = ["45.142.","103.97.","193.106.","185.220.",
                     "91.219.","141.98.","194.165.","209.141.",
                     "5.188.","23.129.","162.33.","198.144."]

def fake_src_ip(aid):
    pref = FAKE_SRC_PREFIXES[aid % len(FAKE_SRC_PREFIXES)]
    return pref + f"{random.randint(1,254)}.{random.randint(1,254)}"

def log_event(ev):
    ev["ts"] = round(time.time() - START_TS, 2)
    ev["wall"] = time.strftime("%H:%M:%S")
    with LOG_LOCK:
        ATTEMPTS.append(ev)

# ---------------- SSH session ----------------
def ssh_session(user, pw, client_banner, commands, timeout=15):
    sock = socket.create_connection((TARGET, SSH_PORT), timeout=timeout)
    t = None
    try:
        t = paramiko.Transport(sock)
        t.local_version = "SSH-2.0-" + client_banner   # per-instance, thread-safe
        t.start_client(timeout=timeout)
        try:
            t.auth_password(user, pw)
            accepted = True
        except paramiko.AuthenticationException:
            accepted = False
        except Exception as e:
            return {"accepted": False, "err": f"{type(e).__name__}: {e}", "opened": False, "responses": []}
        opened = False; responses = []
        if accepted:
            try:
                chan = t.open_session()
                chan.get_pty()
                chan.invoke_shell()
                chan.settimeout(3)
                opened = True
                time.sleep(0.3)
                for cmd in commands:
                    try:
                        chan.send(cmd + "\n")
                        time.sleep(0.3)
                        data = b""
                        try:
                            while True:
                                d = chan.recv(4096)
                                if not d: break
                                data += d
                                if len(data) > 2000: break
                        except socket.timeout:
                            pass
                        responses.append({"cmd": cmd, "out": data.decode(errors="replace")[:240]})
                    except Exception as e:
                        responses.append({"cmd": cmd, "err": str(e)})
                try: chan.close()
                except Exception: pass
            except Exception as e:
                responses.append({"err": f"shell: {e}"})
        return {"accepted": accepted, "opened": opened, "responses": responses}
    except Exception as e:
        return {"accepted": False, "err": f"{type(e).__name__}: {e}", "opened": False, "responses": []}
    finally:
        try:
            if t: t.close()
        except Exception:
            pass

# ---------------- Telnet session ----------------
def telnet_session(user, pw, term, commands, timeout=12):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((TARGET, TEL_PORT))
    except Exception as e:
        return {"accepted": False, "err": f"connect: {e}", "opened": False, "responses": []}
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
            i = 0; out = b""
            while i < len(data):
                if data[i] == 0xFF:
                    if i + 2 < len(data):
                        cmd = data[i+1]; opt = data[i+2]
                        # refuse options; but accept TERM negotiation politely
                        if opt == 24:  # TERM
                            s.send(bytes([0xFF, 251, 24]))  # WILL TERM
                            i += 3; continue
                        s.send(bytes([0xFF, 254 if cmd in (251,253) else 252, opt]))
                        i += 3; continue
                    i += 1; continue
                out += bytes([data[i]]); i += 1
            buf += out
            if any(tok in buf for tok in tokens):
                return True
        return False
    try:
        if not read_until(b"login:"):
            return {"accepted": False, "err": "no login prompt", "opened": False, "responses": []}
        s.send((user + "\r\n").encode())
        if not read_until(b"assword:"):
            return {"accepted": False, "err": "no password prompt", "opened": False, "responses": []}
        s.send((pw + "\r\n").encode())
        # after password, expect either re-login (reject) or shell prompt
        time.sleep(0.5)
        read_until(b"$", tlim=3) or read_until(b"#", tlim=2) or read_until(b"login:", tlim=2)
        accepted = (b"$" in buf or b"#" in buf) and b"login:" not in buf[-40:]
        responses = []
        if accepted:
            for cmd in commands:
                try:
                    s.send((cmd + "\r\n").encode())
                    time.sleep(0.3)
                    read_until(b"$", tlim=2) or read_until(b"#", tlim=2)
                    responses.append({"cmd": cmd, "out": buf[-240:].decode(errors="replace")})
                except Exception as e:
                    responses.append({"cmd": cmd, "err": str(e)})
        return {"accepted": accepted, "opened": accepted, "responses": responses}
    except Exception as e:
        return {"accepted": False, "err": f"{type(e).__name__}: {e}", "opened": False, "responses": []}
    finally:
        try: s.close()
        except Exception:
            pass

# ---------------- attacker worker ----------------
def attacker(aid):
    random.seed(aid * 7919 + int(START_TS))
    src_ip = fake_src_ip(aid)
    banner = CLIENT_BANNERS[aid % len(CLIENT_BANNERS)]
    term = random.choice(["xterm","vt100","linux","ansi"])
    while not STOP.is_set():
        if time.time() - START_TS > DURATION:
            break
        # each wave: try a few creds, on one protocol (sometimes both)
        n_creds = random.randint(2, 4)
        creds = random.sample(CRED_POOL, n_creds)
        cmds = random.sample(CMD_POOL, random.randint(3, 6))
        proto = random.choice(["ssh","telnet","both"])
        targets = []
        if proto in ("ssh","both"): targets.append("ssh")
        if proto in ("telnet","both"): targets.append("telnet")
        for p in targets:
            if STOP.is_set(): break
            user, pw = random.choice(creds)
            try:
                if p == "ssh":
                    r = ssh_session(user, pw, banner, cmds)
                else:
                    r = telnet_session(user, pw, term, cmds)
                log_event({
                    "attacker": f"attacker_{aid:02d}", "src_ip_label": src_ip,
                    "proto": p, "user": user, "pw": pw,
                    "client_banner": ("SSH-2.0-"+banner) if p=="ssh" else f"telnet/{term}",
                    "accepted": r.get("accepted"), "opened": r.get("opened"),
                    "err": r.get("err"),
                    "n_cmds": len(r.get("responses", [])),
                })
            except Exception as e:
                log_event({
                    "attacker": f"attacker_{aid:02d}", "src_ip_label": src_ip,
                    "proto": p, "user": user, "pw": pw,
                    "accepted": False, "opened": False, "err": f"worker: {e}",
                })
        # randomized cadence so the 24 attackers are not synchronized
        if STOP.is_set(): break
        if time.time() - START_TS > DURATION:
            break
        time.sleep(random.uniform(18, 48))

# ---------------- main ----------------
if __name__ == "__main__":
    import paramiko  # imported here so guard runs first
    print(f"[*] Starting simulation: {NUM_ATTACKERS} attackers, {DURATION}s, target {TARGET}:{SSH_PORT}/{TEL_PORT}")
    threads = []
    for i in range(1, NUM_ATTACKERS + 1):
        th = threading.Thread(target=attacker, args=(i,), daemon=True)
        th.start(); threads.append(th)
    # progress printer
    while time.time() - START_TS < DURATION:
        time.sleep(30)
        el = int(time.time() - START_TS)
        with LOG_LOCK:
            n = len(ATTEMPTS)
        print(f"    t={el}s  attempts_so_far={n}")
    STOP.set()
    for th in threads:
        th.join(timeout=10)
    with LOG_LOCK:
        with open(os.path.join(OUTDIR, "attempts.jsonl"), "w", encoding="utf-8") as f:
            for ev in ATTEMPTS:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        meta = {
            "target": TARGET, "ssh_port": SSH_PORT, "telnet_port": TEL_PORT,
            "num_attackers": NUM_ATTACKERS, "duration_s": DURATION,
            "start_wall": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(START_TS)),
            "end_wall": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_attempts": len(ATTEMPTS),
            "real_source_ip": socket.gethostbyname(socket.gethostname()) if False else "test-host-single-ip",
        }
        with open(os.path.join(OUTDIR, "run_meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"[*] DONE. total_attempts={len(ATTEMPTS)} -> attempts.jsonl")
