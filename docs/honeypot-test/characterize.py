#!/usr/bin/env python3
# Characterize honeypot auth behavior (SAFE: only the specified honeypot host/ports).
import paramiko, socket, time

TARGET="172.17.1.203"; SSH_PORT=2222; TEL_PORT=2323

def ssh_try(user, pw, timeout=10):
    try:
        c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(TARGET,port=SSH_PORT,username=user,password=pw,timeout=timeout,
                  look_for_keys=False,allow_agent=False,banner_timeout=timeout)
        # try a command to see if shell is real
        try:
            stdin,stdout,stderr=c.exec_command("id; uname -a",timeout=6)
            out=stdout.read(400).decode(errors="replace"); rc=stdout.channel.recv_exit_status()
            post=f"cmd_ok rc={rc} out={out!r}"
        except Exception as e:
            post=f"cmd_err {type(e).__name__}"
        c.close()
        return f"ACCEPTED | {post}"
    except paramiko.AuthenticationException:
        return "REJECTED"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"

tests=[("root","toor"),("root","root"),("admin","admin"),("administrator","P@ssw0rd"),
       ("zzzqqq","RandomPass#123"),("user","password"),("guest","guest"),("test","test123")]
print("SSH auth characterization:")
for u,p in tests:
    print(f"  {u}:{p} -> {ssh_try(u,p)}")

# Telnet: how many bad attempts before it drops/limits?
def telnet_rounds(user, pw, max_rounds=6, timeout=8):
    s=socket.socket(); s.settimeout(timeout); s.connect((TARGET,TEL_PORT)); buf=b""
    def read_until(tokens,tlim=timeout):
        nonlocal buf; end=time.time()+tlim
        while time.time()<end:
            try: data=s.recv(4096)
            except socket.timeout: break
            if not data: break
            i=0; out=b""
            while i<len(data):
                if data[i]==0xFF:
                    if i+2<len(data):
                        cmd=data[i+1]; opt=data[i+2]
                        s.send(bytes([0xFF,254 if cmd in(251,253) else 252,opt])); i+=3; continue
                    i+=1; continue
                out+=bytes([data[i]]); i+=1
            buf+=out
            if any(t in buf for t in tokens): return True
        return False
    accepted=False; rounds=0
    for _ in range(max_rounds):
        if not read_until(b"login:"): break
        s.send((user+"\r\n").encode())
        if not read_until(b"assword:"): break
        s.send((pw+"\r\n").encode())
        rounds+=1
        # after password, does it drop or re-prompt?
        if read_until(b"login:", tlim=3):
            continue
        else:
            # maybe it gave a shell?
            try:
                s.send(b"exit\r\n"); 
            except: pass
            accepted=True; break
    s.close()
    return rounds, accepted, buf[-120:].decode(errors="replace")

print("\nTelnet repeated bad attempts (admin:wrong):")
print("  rounds, accepted, tail:", telnet_rounds("admin","thisiswrong"))
