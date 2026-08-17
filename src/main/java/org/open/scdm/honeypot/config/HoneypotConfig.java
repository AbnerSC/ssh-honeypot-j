package org.open.scdm.honeypot.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * YAML 配置加载。
 * <p>
 * 配置文件结构示例:
 * <pre>
 * hostname: svr01
 * ssh:
 *   enabled: true
 *   port: 2222
 * telnet:
 *   enabled: true
 *   port: 2323
 * mysql:
 *   enabled: true
 *   port: 3306
 * postgresql:
 *   enabled: true
 *   port: 5432
 * redis:
 *   enabled: true
 *   port: 6379
 * log:
 *   file: logs/honeypot.jsonl
 *   db: logs/database.db
 * web:
 *   enabled: true
 *   port: 8080
 * auth:
 *   maxFailures: 3
 *   windowMinutes: 5
 *   lockMinutes: 30
 *   credentials:
 *     root: "123456"
 *     root: ["123456", "toor", "password"]
 * </pre>
 */
public class HoneypotConfig {

    public static final String DEFAULT_CONFIG_FILE = "config.yaml";

    /** 默认伪装主机名（未配置 Docker hostname 且配置文件未指定 hostname 时的兜底值） */
    public static final String DEFAULT_HOSTNAME = "svr01";

    /** 伪装主机名（config.yaml 中配置），为空时按 {@link #resolveHostname()} 优先级兜底 */
    private String hostname;

    private Ssh ssh = new Ssh();
    private Telnet telnet = new Telnet();
    private Mysql mysql = new Mysql();
    private Postgresql postgresql = new Postgresql();
    private Redis redis = new Redis();
    private Log log = new Log();
    private Web web = new Web();
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

    /** MySQL 蜜罐（模拟 MySQL 8.4，连接即返回 Access denied 并断开） */
    public static class Mysql {
        private boolean enabled = true;
        private int port = 3306;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    /** PostgreSQL 蜜罐（模拟 PostgreSQL 17，连接即返回 password authentication failed 并断开） */
    public static class Postgresql {
        private boolean enabled = true;
        private int port = 5432;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    /** Redis 蜜罐（模拟 Redis 7，连接即返回 WRONGPASS 并断开） */
    public static class Redis {
        private boolean enabled = true;
        private int port = 6379;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    public static class Log {
        private String file = Path.of("logs", "honeypot.jsonl").toString();
        private String db = Path.of("logs", "database.db").toString();

        public String getFile() { return file; }
        public String getDb() { return db; }

        public void setFile(String file) { this.file = file; }
        public void setDb(String db) { this.db = db; }
    }

    /** Web 可视化控制台：攻击日志统计/明细查询 + 系统用户管理，与蜜罐同进程同 jar 部署 */
    public static class Web {
        private boolean enabled = true;   // 是否启用 Web 控制台
        private int port = 8080;          // Web 监听端口
        private int sessionTimeoutMinutes = 30;  // 管理端登录会话超时（分钟）

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }
        public int getSessionTimeoutMinutes() { return sessionTimeoutMinutes; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
        public void setSessionTimeoutMinutes(int sessionTimeoutMinutes) { this.sessionTimeoutMinutes = sessionTimeoutMinutes; }
    }

    /**
     * 登录认证配置：密码本（允许登录的 用户名/密码）+ 失败锁定策略。
     * 未配置 credentials 时使用内置常见弱口令，提升蜜罐被“成功登录”的真实感。
     * <p>
     * credentials 支持两种写法（向后兼容）：
     *   - 单密码：   root: "123456"
     *   - 多密码：   root: ["123456", "toor", "password"]
     * 加载时统一转换为 用户名 -> 密码列表。
     */
    public static class Auth {
        private int maxFailures = 3;    // 连续登录失败达到该次数后锁定源 IP
        private int windowMinutes = 5;  // 失败计数窗口（分钟）：窗口内的连续失败才累计
        private int lockMinutes = 30;   // 源 IP 锁定时长（分钟）
        private Map<String, List<String>> credentials = defaultCredentials();

        private static Map<String, List<String>> defaultCredentials() {
            Map<String, List<String>> map = new LinkedHashMap<>();
            map.put("root", List.of("123456"));
            map.put("admin", List.of("admin123"));
            map.put("ubuntu", List.of("ubuntu"));
            map.put("pi", List.of("raspberry"));
            map.put("test", List.of("test123"));
            return map;
        }

        public int getMaxFailures() { return maxFailures; }
        public int getWindowMinutes() { return windowMinutes; }
        public int getLockMinutes() { return lockMinutes; }
        public Map<String, List<String>> getCredentials() {
            return (credentials == null || credentials.isEmpty()) ? defaultCredentials() : credentials;
        }

        public void setMaxFailures(int maxFailures) { this.maxFailures = maxFailures; }
        public void setWindowMinutes(int windowMinutes) { this.windowMinutes = windowMinutes; }
        public void setLockMinutes(int lockMinutes) { this.lockMinutes = lockMinutes; }

        /**
         * YAML 反序列化入口。兼容两种写法：
         *   - 值为字符串       -> 该账号单个密码
         *   - 值为字符串列表    -> 该账号多个密码
         */
        public void setCredentials(Map<String, Object> raw) {
            Map<String, List<String>> parsed = new LinkedHashMap<>();
            if (raw == null) { credentials = parsed; return; }
            for (Map.Entry<String, Object> e : raw.entrySet()) {
                Object v = e.getValue();
                List<String> list;
                if (v instanceof List<?> l) {
                    list = new ArrayList<>();
                    for (Object item : l) list.add(String.valueOf(item));
                } else {
                    list = new ArrayList<>();
                    list.add(String.valueOf(v));
                }
                parsed.put(e.getKey(), list);
            }
            credentials = parsed;
        }
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

    /**
     * 解析生效的伪装主机名。
     * 优先级：Docker 容器主机名（docker run --hostname / compose hostname）> 配置文件 hostname > 默认值 svr01。
     * <p>
     * Docker 未显式配置 hostname 时容器主机名默认为容器 ID（纯十六进制串），
     * 该情况视为未配置并继续向下兜底，避免蜜罐伪装被随机 ID 破坏。
     */
    public String resolveHostname() {
        if (isRunningInDocker()) {
            String dockerHostname = systemHostname();
            if (dockerHostname != null && !looksLikeContainerId(dockerHostname)) {
                return dockerHostname;
            }
        }
        if (hostname != null && !hostname.isBlank()) {
            return hostname.trim();
        }
        return DEFAULT_HOSTNAME;
    }

    /** 判断是否运行在容器内（/.dockerenv / container 环境变量 / cgroup 特征） */
    private static boolean isRunningInDocker() {
        if (Files.exists(Path.of("/.dockerenv"))) return true;
        String container = System.getenv("container");
        if ("docker".equals(container) || "containerd".equals(container) || "podman".equals(container)) return true;
        try {
            String cgroup = Files.readString(Path.of("/proc/1/cgroup"));
            return cgroup.contains("docker") || cgroup.contains("containerd") || cgroup.contains("kubepods");
        } catch (IOException e) {
            return false; // Windows 等无 /proc 的环境视为非容器
        }
    }

    private static String systemHostname() {
        try {
            String h = InetAddress.getLocalHost().getHostName();
            return (h == null || h.isBlank()) ? null : h;
        } catch (Exception e) {
            return null;
        }
    }

    /** 容器 ID 为纯十六进制串（短 ID 12 位/长 ID 64 位），形似容器 ID 则判定 Docker 未显式配置 hostname */
    private static boolean looksLikeContainerId(String name) {
        return name.length() >= 12 && name.matches("[0-9a-f]+");
    }

    public String getHostname() { return hostname; }
    public Ssh getSsh() { return ssh; }
    public Telnet getTelnet() { return telnet; }
    public Mysql getMysql() { return mysql; }
    public Postgresql getPostgresql() { return postgresql; }
    public Redis getRedis() { return redis; }
    public Log getLog() { return log; }
    public Web getWeb() { return web; }
    public Auth getAuth() { return auth; }

    public void setHostname(String hostname) { this.hostname = hostname; }
    public void setSsh(Ssh ssh) { this.ssh = ssh; }
    public void setTelnet(Telnet telnet) { this.telnet = telnet; }
    public void setMysql(Mysql mysql) { this.mysql = mysql; }
    public void setPostgresql(Postgresql postgresql) { this.postgresql = postgresql; }
    public void setRedis(Redis redis) { this.redis = redis; }
    public void setLog(Log log) { this.log = log; }
    public void setWeb(Web web) { this.web = web; }
    public void setAuth(Auth auth) { this.auth = auth; }
}
