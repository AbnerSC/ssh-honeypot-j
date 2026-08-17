package org.open.scdm.honeypot;

import org.open.scdm.honeypot.auth.CredentialGuard;
import org.open.scdm.honeypot.config.HoneypotConfig;
import org.open.scdm.honeypot.fs.VirtualFileSystem;
import org.open.scdm.honeypot.geo.IpLocator;
import org.open.scdm.honeypot.log.AttackLogger;
import org.open.scdm.honeypot.mysql.MySqlHoneypotServer;
import org.open.scdm.honeypot.postgres.PostgresHoneypotServer;
import org.open.scdm.honeypot.redis.RedisHoneypotServer;
import org.open.scdm.honeypot.ssh.SshHoneypotServer;
import org.open.scdm.honeypot.telnet.TelnetHoneypotServer;
import org.open.scdm.honeypot.web.WebServer;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * SSH/Telnet/数据库蜜罐主入口。
 * <p>
 * 用法:
 *   java -jar ssh-honeypot.jar [选项]
 * <p>
 * 选项:
 *   --config <file>       YAML 配置文件路径（默认 config.yaml）
 *   -h, --help            显示帮助
 * <p>
 * 配置文件格式见 config.yaml，支持 ssh/telnet/mysql/postgresql/redis 开关、端口与日志路径。
 * <p>
 * 生产部署提示：Linux 下用 root 直接监听 22/23/3306/5432/6379，或用 iptables 转发：
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
        // 伪装主机名：优先级 Docker 容器 hostname > config.yaml hostname > 默认 svr01
        String hostname = config.resolveHostname();
        boolean sshEnabled = config.getSsh().isEnabled();
        boolean telnetEnabled = config.getTelnet().isEnabled();
        Path logFile = Path.of(config.getLog().getFile());
        Path dbFile = Path.of(config.getLog().getDb());

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
                  SSH/Telnet/DB 蜜罐  v1.1.0  (Java 25)
                  仅用于安全研究与授权环境，请勿用于非法用途
                ================================================
                """);

        VirtualFileSystem fs = new VirtualFileSystem(hostname);
        // IP 归属地定位器：优先加载外部 ip2region v4/v6 库文件，缺失时回退 jar 内置库，均不可用时自动降级（归属地留空）
        IpLocator ipLocator = IpLocator.load(
                Path.of(config.getLog().getIpdb_v4()), Path.of(config.getLog().getIpdb_v6()));
        AttackLogger attackLogger = new AttackLogger(logFile, dbFile, ipLocator);

        // 凭证守卫：密码本校验 + 连续失败锁定源 IP（状态缓存在内存）
        var authCfg = config.getAuth();
        CredentialGuard guard = new CredentialGuard(
                authCfg.getCredentials(), authCfg.getMaxFailures(),
                authCfg.getWindowMinutes(), authCfg.getLockMinutes(), attackLogger);

        SshHoneypotServer sshServer = null;
        TelnetHoneypotServer telnetServer = null;
        MySqlHoneypotServer mysqlServer = null;
        PostgresHoneypotServer postgresServer = null;
        RedisHoneypotServer redisServer = null;

        if (sshEnabled) {
            sshServer = new SshHoneypotServer(config.getSsh().getPort(), fs, attackLogger, guard, hostname);
            sshServer.start();
        }
        if (telnetEnabled) {
            telnetServer = new TelnetHoneypotServer(config.getTelnet().getPort(), fs, attackLogger, guard, hostname);
            telnetServer.start();
        }
        // 数据库蜜罐：连接即返回默认认证失败信息并立即断开，不做任何协议交互
        if (config.getMysql().isEnabled()) {
            mysqlServer = new MySqlHoneypotServer(config.getMysql().getPort(), attackLogger);
            mysqlServer.start();
        }
        if (config.getPostgresql().isEnabled()) {
            postgresServer = new PostgresHoneypotServer(config.getPostgresql().getPort(), attackLogger);
            postgresServer.start();
        }
        if (config.getRedis().isEnabled()) {
            redisServer = new RedisHoneypotServer(config.getRedis().getPort(), attackLogger);
            redisServer.start();
        }

        // Web 可视化控制台：与蜜罐同进程部署，只读查询 SQLite 攻击日志 + 系统用户管理
        final WebServer[] webServer = {null};
        var webCfg = config.getWeb();
        if (webCfg.isEnabled()) {
            if (attackLogger.isDbHealthy()) {
                webServer[0] = WebServer.start(webCfg.getPort(), webCfg.getSessionTimeoutMinutes(), dbFile, ipLocator);
            } else {
                System.out.println("SQLite 数据库不可用，Web 控制台未启动。");
            }
        }

        System.out.printf("蜜罐运行中: SSH=%s, Telnet=%s, MySQL=%s, PostgreSQL=%s, Redis=%s, Web=%s, 主机名=%s, 日志=%s, 数据库=%s%n",
                sshEnabled ? String.valueOf(config.getSsh().getPort()) : "关闭",
                telnetEnabled ? String.valueOf(config.getTelnet().getPort()) : "关闭",
                config.getMysql().isEnabled() ? String.valueOf(config.getMysql().getPort()) : "关闭",
                config.getPostgresql().isEnabled() ? String.valueOf(config.getPostgresql().getPort()) : "关闭",
                config.getRedis().isEnabled() ? String.valueOf(config.getRedis().getPort()) : "关闭",
                webServer[0] != null ? String.valueOf(webCfg.getPort()) : "关闭",
                hostname, logFile.toAbsolutePath(), dbFile.toAbsolutePath());
        System.out.println("按 Ctrl+C 停止。");

        // 优雅关闭
        CountDownLatch shutdown = new CountDownLatch(1);
        SshHoneypotServer finalSsh = sshServer;
        TelnetHoneypotServer finalTelnet = telnetServer;
        MySqlHoneypotServer finalMysql = mysqlServer;
        PostgresHoneypotServer finalPostgres = postgresServer;
        RedisHoneypotServer finalRedis = redisServer;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n正在关闭蜜罐...");
            try { if (finalSsh != null) finalSsh.stop(); } catch (Exception ignored) {}
            if (finalTelnet != null) finalTelnet.stop();
            if (finalMysql != null) finalMysql.stop();
            if (finalPostgres != null) finalPostgres.stop();
            if (finalRedis != null) finalRedis.stop();
            try { if (webServer[0] != null) webServer[0].stop(); } catch (Exception ignored) {}
            try { attackLogger.close(); } catch (Exception ignored) {}
            ipLocator.close();
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
