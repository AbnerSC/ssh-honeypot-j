package org.open.scdm.honeypot;

import org.open.scdm.honeypot.config.HoneypotConfig;
import org.open.scdm.honeypot.fs.VirtualFileSystem;
import org.open.scdm.honeypot.log.AttackLogger;
import org.open.scdm.honeypot.ssh.SshHoneypotServer;
import org.open.scdm.honeypot.telnet.TelnetHoneypotServer;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * SSH/Telnet 蜜罐主入口。
 * <p>
 * 用法:
 *   java -jar ssh-honeypot.jar [选项]
 * <p>
 * 选项:
 *   --config <file>       YAML 配置文件路径（默认 config.yaml）
 *   -h, --help            显示帮助
 * <p>
 * 配置文件格式见 config.yaml，支持 ssh/telnet 开关、端口与日志路径。
 * <p>
 * 生产部署提示：Linux 下用 root 直接监听 22/23，或用 iptables 转发：
 *   iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
 *   iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
 */
public class Main {
    static void main(String[] args) throws Exception {
        String configPath = HoneypotConfig.DEFAULT_CONFIG_FILE;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--config", "-c" -> configPath = args[++i];
                case "--help", "-h" -> { printUsage(); return; }
                default -> System.err.println("未知参数: " + args[i]);
            }
        }

        HoneypotConfig config = HoneypotConfig.load(configPath);
        boolean sshEnabled = config.getSsh().isEnabled();
        boolean telnetEnabled = config.getTelnet().isEnabled();
        Path logFile = Path.of(config.getLog().getFile());

        // 日志格式精简
        Logger root = Logger.getLogger("");
        for (var h : root.getHandlers()) root.removeHandler(h);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new SimpleFormatter());
        handler.setLevel(Level.INFO);
        root.addHandler(handler);
        root.setLevel(Level.INFO);

        System.out.println("""
                ================================================
                  SSH/Telnet 蜜罐  v1.0.2  (Java 25)
                  仅用于安全研究与授权环境，请勿用于非法用途
                ================================================
                """);

        VirtualFileSystem fs = new VirtualFileSystem();
        AttackLogger attackLogger = new AttackLogger(logFile);

        SshHoneypotServer sshServer = null;
        TelnetHoneypotServer telnetServer = null;

        if (sshEnabled) {
            sshServer = new SshHoneypotServer(config.getSsh().getPort(), fs, attackLogger);
            sshServer.start();
        }
        if (telnetEnabled) {
            telnetServer = new TelnetHoneypotServer(config.getTelnet().getPort(), fs, attackLogger);
            telnetServer.start();
        }

        System.out.printf("蜜罐运行中: SSH=%s, Telnet=%s, 日志=%s%n",
                sshEnabled ? String.valueOf(config.getSsh().getPort()) : "关闭",
                telnetEnabled ? String.valueOf(config.getTelnet().getPort()) : "关闭",
                logFile.toAbsolutePath());
        System.out.println("按 Ctrl+C 停止。");

        // 优雅关闭
        CountDownLatch shutdown = new CountDownLatch(1);
        SshHoneypotServer finalSsh = sshServer;
        TelnetHoneypotServer finalTelnet = telnetServer;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n正在关闭蜜罐...");
            try { if (finalSsh != null) finalSsh.stop(); } catch (Exception ignored) {}
            if (finalTelnet != null) finalTelnet.stop();
            try { attackLogger.close(); } catch (Exception ignored) {}
            shutdown.countDown();
        }, "honeypot-shutdown"));

        shutdown.await(); // 主线程挂起直到关闭完成
    }

    private static void printUsage() {
        System.out.println("""
                用法: java -jar ssh-honeypot.jar [选项]
                  -c, --config <file>   YAML 配置文件路径（默认 config.yaml）
                  -h, --help            显示帮助
                """);
    }
}
