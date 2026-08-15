package org.open.scdm.honeypot.telnet;

import org.open.scdm.honeypot.auth.CredentialGuard;
import org.open.scdm.honeypot.fs.VirtualFileSystem;
import org.open.scdm.honeypot.log.AttackLogger;
import org.open.scdm.honeypot.shell.CommandProcessor;
import org.open.scdm.honeypot.shell.FakeShell;
import org.open.scdm.honeypot.shell.SessionState;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Telnet 蜜罐服务（原生 Socket 实现，含 IAC 协商）。
 * 模拟经典 Linux login 提示符，按密码本校验凭证；
 * 单连接最多重试 maxFailures 次，连续失败达阈值后锁定源 IP。
 */
public class TelnetHoneypotServer {
    private static final Logger LOG = Logger.getLogger(TelnetHoneypotServer.class.getName());

    // Telnet 协议字节
    private static final int IAC = 255, WILL = 251, WONT = 252, DO = 253, DONT = 254, SB = 250, SE = 240;
    private static final int ECHO = 1, SUPPRESS_GO_AHEAD = 3, TERMINAL_TYPE = 24, NAWS = 31, LINEMODE = 34;

    private final int port;
    private final VirtualFileSystem fs;
    private final AttackLogger logger;
    private final CommandProcessor processor;
    private final CredentialGuard guard;
    /** 伪装主机名，用于 login 提示符（如 svr01 login:） */
    private final String hostname;
    /** 虚拟线程执行器：每个连接一条虚拟线程，替代 cachedThreadPool 平台线程，大幅降低并发连接内存开销 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public TelnetHoneypotServer(int port, VirtualFileSystem fs, AttackLogger logger, CredentialGuard guard, String hostname) {
        this.port = port;
        this.fs = fs;
        this.logger = logger;
        this.guard = guard;
        this.hostname = hostname;
        this.processor = new CommandProcessor(logger, hostname);
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("Telnet 蜜罐已启动，监听端口 " + port);
        pool.submit(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    pool.submit(() -> handleClient(client));
                } catch (IOException e) {
                    if (running) LOG.warning("Telnet accept 失败: " + e.getMessage());
                }
            }
        });
    }

    public void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        pool.shutdownNow();
    }

    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        int clientPort = socket.getPort();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "telnet", ip, clientPort);
        long start = System.currentTimeMillis();
        try (socket) {
            socket.setSoTimeout(10 * 60 * 1000); // 10 分钟无操作自动断开
            PushbackInputStream in = new PushbackInputStream(socket.getInputStream(), 1);
            OutputStream out = socket.getOutputStream();

            negotiate(out);

            // 经典 login 流程：按密码本校验，每次尝试均记录日志
            out.write("\r\nUbuntu 22.04.3 LTS\r\n".getBytes());
            out.flush();
            String username = null;
            boolean authed = false;
            for (int attempt = 0; attempt < guard.getMaxFailures(); attempt++) {
                if (guard.isLocked(ip)) {
                    out.write("\r\nToo many failed attempts. Connection locked.\r\n".getBytes());
                    out.flush();
                    break;
                }
                String u = promptLine(in, out, hostname + " login: ", true);
                if (u == null) break;                          // 客户端断开
                String p = promptLine(in, out, "Password: ", false);
                if (p == null) p = "";
                username = u.trim();
                boolean ok = guard.authenticate(ip, username, p.trim());
                logger.authAttempt(sessionId, "telnet", ip, username, p.trim(), ok);
                if (ok) {
                    authed = true;
                    break;
                }
                out.write("\r\nLogin incorrect\r\n".getBytes());
                out.flush();
            }
            if (!authed) {
                // 认证失败（凭证错误/被锁定/客户端断开）：记录会话关闭后断开
                logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
                return;
            }
            out.write("\r\n".getBytes());
            out.flush();

            // 进入伪 Shell
            SessionState state = new SessionState(sessionId, ip, username, fs, hostname);
            FakeShell shell = new FakeShell(in, out, state, processor, logger, st -> {});
            shell.run();

        } catch (IOException e) {
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }

    /** 服务端主动协商：我们负责回显，客户端逐字符发送 */
    private void negotiate(OutputStream out) throws IOException {
        out.write(new byte[]{
                (byte) IAC, (byte) WILL, (byte) ECHO,
                (byte) IAC, (byte) WILL, (byte) SUPPRESS_GO_AHEAD,
                (byte) IAC, (byte) DO,   (byte) SUPPRESS_GO_AHEAD,
                (byte) IAC, (byte) DO,   (byte) NAWS,
                (byte) IAC, (byte) DONT, (byte) LINEMODE,
        });
        out.flush();
    }

    /** 读取一行（login 阶段用，兼容逐字符与整行两种客户端） */
    private String promptLine(PushbackInputStream in, OutputStream out, String prompt, boolean echo) throws IOException {
        out.write(prompt.getBytes());
        out.flush();
        StringBuilder buf = new StringBuilder();
        boolean lastWasCR = false;
        while (true) {
            int b = in.read();
            if (b == -1) return null;
            if (b == IAC) { skipTelnetCommand(in); continue; }
            if (b == 27) { skipEscape(in); continue; }
            if (b == '\r') {
                // 吃掉 \r\n 中的 \n；不是 \n 则放回留给后续读取
                int next = in.read();
                if (next != '\n' && next != -1) in.unread(next);
                break;
            }
            if (b == '\n') {
                if (lastWasCR) { lastWasCR = false; continue; }
                break;
            }
            lastWasCR = false;
            if (b == 8 || b == 127) {
                if (buf.length() > 0) {
                    buf.setLength(buf.length() - 1);
                    if (echo) out.write(new byte[]{8, ' ', 8});
                }
                continue;
            }
            if (b < 0x20) continue;
            buf.append((char) b);
            if (echo) out.write(b); else out.write('*'); // 密码不回显明文
            out.flush();
        }
        out.write("\r\n".getBytes());
        out.flush();
        return buf.toString();
    }

    private void skipTelnetCommand(InputStream in) throws IOException {
        int cmd = in.read();
        if (cmd == -1) return;
        if (cmd >= WILL && cmd <= DONT) {
            in.read();
        } else if (cmd == SB) {
            int prev = -1, cur;
            while ((cur = in.read()) != -1) {
                if (prev == IAC && cur == SE) break;
                prev = cur;
            }
        }
    }

    private void skipEscape(InputStream in) throws IOException {
        int b = in.read();
        if (b == '[' || b == 'O') {
            int c;
            while ((c = in.read()) >= 0x30 && c <= 0x3F) { /* 吞掉参数 */ }
        }
    }
}
