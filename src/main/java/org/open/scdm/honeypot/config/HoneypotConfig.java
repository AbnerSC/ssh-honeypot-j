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
 *   ipdb_v4: db/ip2region_v4.xdb
 *   ipdb_v6: db/ip2region_v6.xdb
 * ai:
 *   enabled: true
 *   base_url: http://host:port/v1
 *   api_key: xxx
 *   model_name: xxx
 *   enable_thinking: false
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
    private Ai ai = new Ai();

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

    /** MySQL 蜜罐（模拟 MySQL 8.4，握手捕获登录凭证后一律返回 Access denied 并断开；最大并发连接 20，超限返回 Too many connections） */
    public static class Mysql {
        private boolean enabled = true;
        private int port = 3306;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    /** PostgreSQL 蜜罐（模拟 PostgreSQL 17，捕获登录凭证明文后一律返回 password authentication failed 并断开；最大并发连接 20） */
    public static class Postgresql {
        private boolean enabled = true;
        private int port = 5432;

        public boolean isEnabled() { return enabled; }
        public int getPort() { return port; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setPort(int port) { this.port = port; }
    }

    /** Redis 蜜罐（模拟 Redis 7，捕获 AUTH 登录凭证明文后一律返回 WRONGPASS 并断开；最大并发连接 20） */
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
        /** IPv4 归属地离线库文件（ip2region xdb），文件缺失时回退 jar 内置库，可选覆盖项 */
        private String ipdb_v4 = Path.of("db", "ip2region_v4.xdb").toString();
        /** IPv6 归属地离线库文件（ip2region xdb），文件缺失时回退 jar 内置库，可选覆盖项 */
        private String ipdb_v6 = Path.of("db", "ip2region_v6.xdb").toString();

        public String getFile() { return file; }
        public String getDb() { return db; }
        public String getIpdb_v4() { return ipdb_v4; }
        public String getIpdb_v6() { return ipdb_v6; }

        public void setFile(String file) { this.file = file; }
        public void setDb(String db) { this.db = db; }
        public void setIpdb_v4(String ipdb_v4) { this.ipdb_v4 = ipdb_v4; }
        public void setIpdb_v6(String ipdb_v6) { this.ipdb_v6 = ipdb_v6; }
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
     * 大模型命令仿真配置：为伪 Shell 未覆盖的未知命令生成仿真终端输出。
     * 未启用（enabled=false）或关键配置缺失时，AiClient 不创建，
     * 未知命令一律降级本地兜底 "-bash: xxx: command not found"。
     * <p>
     * 字段名与 YAML 键同名（snake_case，与 ipdb_v4 同风格），由 SnakeYAML 按属性名精确映射。
     */
    public static class Ai {
        private boolean enabled = false;
        private String base_url = "";
        private String api_key = "";
        private String model_name = "";
        /** 是否开启模型思考模式（混合推理模型经 chat_template_kwargs 透传；开启后响应更慢，建议调大 timeout_seconds） */
        private boolean enable_thinking = false;
        /** 单次请求超时（秒），超时立即降级本地兜底 */
        private int timeout_seconds = 20;
        /** 单条输出最大字符数：超长截断，防长输出撑爆小堆内存 */
        private int max_output_chars = 8192;
        /** 全局并发请求上限：超出的命令立即降级不排队，防大模型服务被打爆 */
        private int max_concurrent = 4;
        /** 连续失败达到该次数后触发熔断 */
        private int failure_threshold = 3;
        /** 熔断时长（秒）：期间不再请求 AI，未知命令直接本地兜底 */
        private int cooldown_seconds = 300;

        public boolean isEnabled() { return enabled; }
        public String getBase_url() { return base_url; }
        public String getApi_key() { return api_key; }
        public String getModel_name() { return model_name; }
        public boolean isEnable_thinking() { return enable_thinking; }
        public int getTimeout_seconds() { return timeout_seconds; }
        public int getMax_output_chars() { return max_output_chars; }
        public int getMax_concurrent() { return max_concurrent; }
        public int getFailure_threshold() { return failure_threshold; }
        public int getCooldown_seconds() { return cooldown_seconds; }

        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public void setBase_url(String base_url) { this.base_url = base_url; }
        public void setApi_key(String api_key) { this.api_key = api_key; }
        public void setModel_name(String model_name) { this.model_name = model_name; }
        public void setEnable_thinking(boolean enable_thinking) { this.enable_thinking = enable_thinking; }
        public void setTimeout_seconds(int timeout_seconds) { this.timeout_seconds = timeout_seconds; }
        public void setMax_output_chars(int max_output_chars) { this.max_output_chars = max_output_chars; }
        public void setMax_concurrent(int max_concurrent) { this.max_concurrent = max_concurrent; }
        public void setFailure_threshold(int failure_threshold) { this.failure_threshold = failure_threshold; }
        public void setCooldown_seconds(int cooldown_seconds) { this.cooldown_seconds = cooldown_seconds; }
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
    public Ai getAi() { return ai; }

    public void setHostname(String hostname) { this.hostname = hostname; }
    public void setSsh(Ssh ssh) { this.ssh = ssh; }
    public void setTelnet(Telnet telnet) { this.telnet = telnet; }
    public void setMysql(Mysql mysql) { this.mysql = mysql; }
    public void setPostgresql(Postgresql postgresql) { this.postgresql = postgresql; }
    public void setRedis(Redis redis) { this.redis = redis; }
    public void setLog(Log log) { this.log = log; }
    public void setWeb(Web web) { this.web = web; }
    public void setAuth(Auth auth) { this.auth = auth; }
    public void setAi(Ai ai) { this.ai = ai; }
}
