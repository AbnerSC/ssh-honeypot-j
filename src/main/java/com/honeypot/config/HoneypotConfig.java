package com.honeypot.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * YAML 配置加载。
 *
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
 * </pre>
 */
public class HoneypotConfig {

    public static final String DEFAULT_CONFIG_FILE = "config.yaml";

    private Ssh ssh = new Ssh();
    private Telnet telnet = new Telnet();
    private Log log = new Log();

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

    public void setSsh(Ssh ssh) { this.ssh = ssh; }
    public void setTelnet(Telnet telnet) { this.telnet = telnet; }
    public void setLog(Log log) { this.log = log; }
}
