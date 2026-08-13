package org.open.scdm.honeypot.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * YAML 配置加载。
 * <p>
 * 配置文件结构示例:
 * <pre>
 * ssh:
 *   enabled: true
 *   port: 2222
 * telnet:
 *   enabled: true
 *   port: 2323
 * log:
 *   file: logs/honeypot.jsonl
 * auth:
 *   maxFailures: 3
 *   lockMinutes: 30
 *   credentials:
 *     root: "123456"
 * </pre>
 */
public class HoneypotConfig {

    public static final String DEFAULT_CONFIG_FILE = "config.yaml";

    private Ssh ssh = new Ssh();
    private Telnet telnet = new Telnet();
    private Log log = new Log();
    private Auth auth = new Auth();

    public static class Ssh {
        private boolean enabled = true;
        private int port = 2222;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    public static class Telnet {
        private boolean enabled = true;
        private int port = 2323;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    public static class Log {
        private String file = Path.of("logs", "honeypot.jsonl").toString();

        public String getFile() { return file; }

        public void setFile(String file) { this.file = file; }
    }

    /**
     * 登录认证配置：密码本（允许登录的 用户名/密码）+ 失败锁定策略。
     * 未配置 credentials 时使用内置常见弱口令，提升蜜罐被“成功登录”的真实感。
     */
    public static class Auth {
        private int maxFailures = 3;    // 连续登录失败达到该次数后锁定源 IP
        private int lockMinutes = 30;   // 源 IP 锁定时长（分钟）
        private Map<String, String> credentials = defaultCredentials();

        private static Map<String, String> defaultCredentials() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("root", "123456");
            map.put("admin", "admin123");
            map.put("ubuntu", "ubuntu");
            map.put("pi", "raspberry");
            map.put("test", "test123");
            return map;
        }

        public int getMaxFailures() { return maxFailures; }
        public int getLockMinutes() { return lockMinutes; }
        public Map<String, String> getCredentials() {
            return (credentials == null || credentials.isEmpty()) ? defaultCredentials() : credentials;
        }

        public void setMaxFailures(int maxFailures) { this.maxFailures = maxFailures; }
        public void setLockMinutes(int lockMinutes) { this.lockMinutes = lockMinutes; }
        public void setCredentials(Map<String, String> credentials) { this.credentials = credentials; }
    }

    /**
     * 从指定路径加载配置；文件不存在时使用内置默认值。
     */
    public static HoneypotConfig load(String path) throws IOException {
        Path file = Path.of(path);
        if (!Files.exists(file)) {
            System.out.println("未找到配置文件 " + file.toAbsolutePath() + "，使用默认配置。");
            return new HoneypotConfig();
        }

        LoaderOptions options = new LoaderOptions();
        Yaml yaml = new Yaml(new Constructor(HoneypotConfig.class, options));
        try (InputStream in = Files.newInputStream(file)) {
            HoneypotConfig config = yaml.load(in);
            if (config == null) {
                config = new HoneypotConfig();
            }
            return config;
        }
    }

    public Ssh getSsh() { return ssh; }
    public Telnet getTelnet() { return telnet; }
    public Log getLog() { return log; }
    public Auth getAuth() { return auth; }

    public void setSsh(Ssh ssh) { this.ssh = ssh; }
    public void setTelnet(Telnet telnet) { this.telnet = telnet; }
    public void setLog(Log log) { this.log = log; }
    public void setAuth(Auth auth) { this.auth = auth; }
}
