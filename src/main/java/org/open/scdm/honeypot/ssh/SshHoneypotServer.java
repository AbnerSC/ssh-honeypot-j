package org.open.scdm.honeypot.ssh;

import org.open.scdm.honeypot.fs.VirtualFileSystem;
import org.open.scdm.honeypot.log.AttackLogger;
import org.open.scdm.honeypot.shell.CommandProcessor;
import org.open.scdm.honeypot.shell.FakeShell;
import org.open.scdm.honeypot.shell.SessionState;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * SSH 蜜罐服务（基于 Apache MINA SSHD）。
 * 特点：
 *  - 伪装成 OpenSSH_8.9p1 (Ubuntu)
 *  - 任意用户名/密码均可"登录成功"，凭证全部记录
 *  - 支持交互式 shell 与 exec 两种攻击方式
 */
public class SshHoneypotServer {
    private static final Logger LOG = Logger.getLogger(SshHoneypotServer.class.getName());

    private final int port;
    private final VirtualFileSystem fs;
    private final AttackLogger logger;
    private final CommandProcessor processor;
    private SshServer sshd;

    /** sessionId -> 登录用户名（auth 阶段写入，shell 阶段读取） */
    private final Map<String, String> sessionUsers = new ConcurrentHashMap<>();

    public SshHoneypotServer(int port, VirtualFileSystem fs, AttackLogger logger) {
        this.port = port;
        this.fs = fs;
        this.logger = logger;
        this.processor = new CommandProcessor(logger);
    }

    public void start() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        CoreModuleProperties.SERVER_IDENTIFICATION.set(sshd, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4");
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Path.of("hostkey.ser")));

        // 密码认证：全部放行并记录
        sshd.setPasswordAuthenticator((username, password, session) -> {
            String ip = clientIp(session);
            String sid = logger.newSessionId();
            sessionUsers.put(sessionKey(session), username);
            logger.authAttempt(sid, "ssh", ip, username, password, true);
            logger.sessionOpen(sid, "ssh", ip, clientPort(session));
            return true;
        });

        // 公钥认证：记录指纹，拒绝（攻击者极少有合法公钥，拒绝更像真实主机）
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            logger.authAttempt(logger.newSessionId(), "ssh", clientIp(session),
                    username, "[pubkey:" + key.getAlgorithm() + "]", false);
            return false;
        });

        // 交互式 shell
        sshd.setShellFactory(channel -> new ShellCommand(channel));

        // exec 方式（ssh user@host "cmd"）——自动化 bot 常用
        sshd.setCommandFactory((channel, command) -> new ExecCommand(channel, command));

        sshd.start();
        LOG.info("SSH 蜜罐已启动，监听端口 " + port);
    }

    public void stop() throws IOException {
        if (sshd != null) sshd.stop(true);
    }

    private String sessionKey(Session session) {
        return String.valueOf(session.getIoSession().getId());
    }

    private String clientIp(Session session) {
        if (session.getIoSession().getRemoteAddress() instanceof InetSocketAddress addr) {
            return addr.getAddress().getHostAddress();
        }
        return "unknown";
    }

    private int clientPort(Session session) {
        if (session.getIoSession().getRemoteAddress() instanceof InetSocketAddress addr) {
            return addr.getPort();
        }
        return 0;
    }

    /* ------------------------------------------------------------------ */
    /* 交互式 Shell 命令                                                    */
    /* ------------------------------------------------------------------ */

    private class ShellCommand implements Command {
        private final ChannelSession channel;
        private InputStream in;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback callback;
        private FakeShell shell;
        private Thread thread;

        ShellCommand(ChannelSession channel) {
            this.channel = channel;
        }

        @Override public void setInputStream(InputStream in) { this.in = in; }
        @Override public void setOutputStream(OutputStream out) { this.out = out; }
        @Override public void setErrorStream(OutputStream err) { this.err = err; }
        @Override public void setExitCallback(ExitCallback callback) { this.callback = callback; }

        @Override
        public void start(ChannelSession ch, Environment env) {
            Session session = ch.getSession();
            String username = sessionUsers.getOrDefault(sessionKey(session), "root");
            String ip = clientIp(session);
            SessionState state = new SessionState(logger.newSessionId(), ip, username, fs);
            logger.sessionOpen(state.sessionId, "ssh-shell", ip, clientPort(session));

            shell = new FakeShell(in, out, state, processor, logger,
                    st -> callback.onExit(0));
            // 虚拟线程：每个交互会话一条，海量并发下几乎零调度开销
            thread = Thread.ofVirtual().name("ssh-shell-" + state.sessionId).start(shell::run);
        }

        @Override
        public void destroy(ChannelSession ch) {
            if (shell != null) shell.stop();
            if (thread != null) thread.interrupt();
            try { if (in != null) in.close(); } catch (IOException ignored) {}
        }
    }

    /* ------------------------------------------------------------------ */
    /* exec 命令（非交互）                                                   */
    /* ------------------------------------------------------------------ */

    private class ExecCommand implements Command {
        private final ChannelSession channel;
        private final String command;
        private OutputStream out;
        private ExitCallback callback;
        private Thread thread;

        ExecCommand(ChannelSession channel, String command) {
            this.channel = channel;
            this.command = command;
        }

        @Override public void setInputStream(InputStream in) {}
        @Override public void setOutputStream(OutputStream out) { this.out = out; }
        @Override public void setErrorStream(OutputStream err) {}
        @Override public void setExitCallback(ExitCallback callback) { this.callback = callback; }

        @Override
        public void start(ChannelSession ch, Environment env) {
            // 虚拟线程：exec 攻击通常短平快，虚拟线程创建/销毁成本可忽略
            thread = Thread.ofVirtual().name("ssh-exec").start(() -> {
                try {
                    Session session = channel.getSession();
                    String username = sessionUsers.getOrDefault(sessionKey(session), "root");
                    String ip = clientIp(session);
                    SessionState state = new SessionState(logger.newSessionId(), ip, username, fs);
                    String result = processor.execute(state, command);
                    if (!CommandProcessor.EXIT_SIGNAL.equals(result) && result != null) {
                        out.write(result.replace("\u0000NONL", "").getBytes());
                        out.flush();
                    }
                } catch (Exception ignored) {
                } finally {
                    callback.onExit(0);
                }
            });
        }

        @Override
        public void destroy(ChannelSession ch) {
            if (thread != null) thread.interrupt();
        }
    }
}
