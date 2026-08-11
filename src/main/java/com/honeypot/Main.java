package com.honeypot;

import com.honeypot.fs.VirtualFileSystem;
import com.honeypot.log.AttackLogger;
import com.honeypot.ssh.SshHoneypotServer;
import com.honeypot.telnet.TelnetHoneypotServer;

import java.nio.file.Path;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * SSH/Telnet 蜜罐主入口。
 *
 * 用法:
 *   java -jar ssh-honeypot.jar [选项]
 *
 * 选项:
 *   --ssh-port <port>     SSH 监听端口（默认 2222）
 *   --telnet-port <port>  Telnet 监听端口（默认 2323）
 *   --no-ssh              禁用 SSH 服务
 *   --no-telnet           禁用 Telnet 服务
 *   --log <file>          攻击日志文件（默认 logs/honeypot.jsonl）
 *
 * 生产部署提示：Linux 下用 root 直接监听 22/23，或用 iptables 转发：
 *   iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
 *   iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
 */
public class Main {
    public static void main(String[] args) throws Exception {
        int sshPort = 2222;
        int telnetPort = 2323;
        boolean sshEnabled = true;
        boolean telnetEnabled = true;
        Path logFile = Path.of("logs", "honeypot.jsonl");

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--ssh-port" -> sshPort = Integer.parseInt(args[++i]);
                case "--telnet-port" -> telnetPort = Integer.parseInt(args[++i]);
                case "--no-ssh" -> sshEnabled = false;
                case "--no-telnet" -> telnetEnabled = false;
                case "--log" -> logFile = Path.of(args[++i]);
                case "--help", "-h" -> { printUsage(); return; }
                default -> System.err.println("未知参数: " + args[i]);
            }
        }

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
                  SSH/Telnet 蜜罐  v1.0  (Java 21)
                  仅用于安全研究与授权环境，请勿用于非法用途
                ================================================
                """);

        VirtualFileSystem fs = new VirtualFileSystem();
        AttackLogger attackLogger = new AttackLogger(logFile);

        SshHoneypotServer sshServer = null;
        TelnetHoneypotServer telnetServer = null;

        if (sshEnabled) {
            sshServer = new SshHoneypotServer(sshPort, fs, attackLogger);
            sshServer.start();
        }
        if (telnetEnabled) {
            telnetServer = new TelnetHoneypotServer(telnetPort, fs, attackLogger);
            telnetServer.start();
        }

        System.out.printf("蜜罐运行中: SSH=%s, Telnet=%s, 日志=%s%n",
                sshEnabled ? String.valueOf(sshPort) : "关闭",
                telnetEnabled ? String.valueOf(telnetPort) : "关闭",
                logFile.toAbsolutePath());
        System.out.println("按 Ctrl+C 停止。");

        // 优雅关闭
        SshHoneypotServer finalSsh = sshServer;
        TelnetHoneypotServer finalTelnet = telnetServer;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n正在关闭蜜罐...");
            try { if (finalSsh != null) finalSsh.stop(); } catch (Exception ignored) {}
            if (finalTelnet != null) finalTelnet.stop();
            try { attackLogger.close(); } catch (Exception ignored) {}
        }));

        Thread.currentThread().join(); // 主线程挂起
    }

    private static void printUsage() {
        System.out.println("""
                用法: java -jar ssh-honeypot.jar [选项]
                  --ssh-port <port>     SSH 监听端口（默认 2222）
                  --telnet-port <port>  Telnet 监听端口（默认 2323）
                  --no-ssh              禁用 SSH 服务
                  --no-telnet           禁用 Telnet 服务
                  --log <file>          攻击日志文件（默认 logs/honeypot.jsonl）
                """);
    }
}
