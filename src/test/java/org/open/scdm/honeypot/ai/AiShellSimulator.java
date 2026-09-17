package org.open.scdm.honeypot.ai;

import org.open.scdm.honeypot.config.HoneypotConfig;
import org.open.scdm.honeypot.fs.VirtualFileSystem;
import org.open.scdm.honeypot.geo.IpLocator;
import org.open.scdm.honeypot.log.AttackLogger;
import org.open.scdm.honeypot.shell.CommandProcessor;
import org.open.scdm.honeypot.shell.SessionState;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * 本地模拟测试驱动：在开发机上复现“攻击者登录伪 Shell 执行命令”的完整链路，
 * 无需真实攻击流量即可验证大模型命令仿真效果。走生产代码路径：
 * CommandProcessor.execute -> switch 命令表 -> 未命中 aiFallback -> AiClient -> 降级兜底。
 * <p>
 * 用法:
 * <pre>
 *   java org.open.scdm.honeypot.ai.AiShellSimulator [选项]
 *     --auto            自动跑预设攻击场景（本地命令 / AI 仿真 / 服务不可达降级）并汇总耗时
 *     --thinking        追加思考模式对比（同一命令 关/开 各执行一次，观察耗时与输出差异）
 *     --config &lt;file&gt;   配置文件路径（默认 config.yaml）
 *     （默认）交互模式：模拟攻击者会话，任意输入命令实时观察输出，exit 退出
 * </pre>
 * config.yaml 默认关闭 AI，测试时可设环境变量注入（优先级高于配置文件）：
 * <pre>
 *   AI_ENABLED=true AI_BASE_URL=http://127.0.0.1:18000 AI_MODEL_NAME=qwen3-2b
 * </pre>
 * 测试日志隔离写入 target/ai-sim/，不污染 logs/ 生产日志。
 */
public final class AiShellSimulator {
    /** 模拟攻击者来源 IP：TEST-NET-3 文档地址，与 FakeShell 内 last 命令展示保持一致 */
    private static final String ATTACKER_IP = "203.0.113.44";

    /** 自动场景：命令 + 预期路由（展示用） */
    private record Scenario(String cmd, String expect) {}

    private static final List<Scenario> SCENARIOS = List.of(
            new Scenario("whoami", "本地硬编码"),
            new Scenario("ls -la /tmp", "本地硬编码（虚拟文件系统）"),
            new Scenario("cat /etc/passwd", "本地硬编码"),
            new Scenario("nmap -sS -T4 10.0.0.0/24", "AI 仿真（未装工具时模型如实回 not found）"),
            new Scenario("./kdevtmpfsi -o pool.supportxmr.com:3333", "AI 仿真（恶意样本名）"),
            new Scenario("docker ps -a", "本地硬编码（伪造容器列表）"),
            new Scenario("docker-compose -v", "AI 仿真（未命中本地命令表）"),
            new Scenario("git log --oneline -3", "AI 仿真（携带前序命令上下文）")
    );

    public static void main(String[] args) throws Exception {
        String configPath = "config.yaml";
        boolean auto = false;
        boolean thinking = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--auto" -> auto = true;
                case "--thinking" -> thinking = true;
                case "--config", "-c" -> configPath = args[++i];
                default -> { System.out.println("未知参数: " + args[i]); return; }
            }
        }

        // 日志格式精简（与 Main 一致），避免 JUL 默认冗长输出干扰测试结果展示
        Logger root = Logger.getLogger("");
        for (var h : root.getHandlers()) root.removeHandler(h);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new SimpleFormatter());
        handler.setLevel(Level.INFO);
        root.addHandler(handler);
        root.setLevel(Level.INFO);

        HoneypotConfig config = HoneypotConfig.load(configPath);
        String hostname = config.resolveHostname();
        AiClient ai = AiClient.create(config.getAi());
        System.out.println("==================================================");
        System.out.println(" AI 命令仿真本地模拟测试  主机=" + hostname
                + "  AI=" + (ai != null ? config.getAi().getModel_name() : "未启用（未知命令走本地兜底）"));
        System.out.println("==================================================");

        // 测试日志隔离：target/ai-sim/ 下双写 JSONL + SQLite，不碰生产日志
        Path simDir = Path.of("target", "ai-sim");
        Files.createDirectories(simDir);
        IpLocator ipLocator = IpLocator.load(
                Path.of(config.getLog().getIpdb_v4()), Path.of(config.getLog().getIpdb_v6()));
        AttackLogger attackLogger = new AttackLogger(
                simDir.resolve("honeypot.jsonl"), simDir.resolve("database.db"), ipLocator);

        VirtualFileSystem fs = new VirtualFileSystem(hostname);
        SessionState st = new SessionState("ai-sim-test", ATTACKER_IP, "root", fs, hostname);
        CommandProcessor processor = new CommandProcessor(attackLogger, hostname, ai);

        try {
            if (auto) runAuto(processor, st, attackLogger, thinking, config);
            else runInteractive(processor, st);
        } finally {
            if (ai != null) ai.close();
            attackLogger.close();
            ipLocator.close();
            System.out.println("\n测试日志已写入: " + simDir.toAbsolutePath());
        }
    }

    /* ------------------------------------------------------------------ */
    /* --auto：预设攻击场景自动执行                                          */
    /* ------------------------------------------------------------------ */

    private static void runAuto(CommandProcessor processor, SessionState st,
                                AttackLogger attackLogger, boolean thinking, HoneypotConfig config) throws Exception {
        List<String[]> stats = new ArrayList<>(); // [场景, 预期, 耗时]
        int i = 1;
        for (Scenario s : SCENARIOS) {
            stats.add(runOne(processor, st, i++, SCENARIOS.size(), s.cmd(), s.expect()));
        }

        // 降级场景：AI 服务不可达（连接 127.0.0.1:9 被拒），未知命令应毫秒级回退本地兜底
        System.out.println("\n--- 场景 " + i + "/" + (SCENARIOS.size() + 1)
                + "  [预期: AI 不可达自动降级本地兜底] ---");
        try (AiClient dead = AiClient.create(deadConfig())) {
            CommandProcessor degraded = new CommandProcessor(attackLogger, st.hostname, dead);
            long t0 = System.nanoTime();
            String out = degraded.execute(st, "nmap -sV 192.168.1.1");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            printOutput("nmap -sV 192.168.1.1", out);
            stats.add(new String[]{"nmap -sV 192.168.1.1（AI 不可达）", "降级本地兜底", ms + "ms"});
        }

        if (thinking) {
            runThinkingCompare(st, config);
        }

        System.out.println("\n==================== 汇总 ====================");
        for (String[] row : stats) {
            System.out.printf("  %-58s %-28s %8s%n", row[0], "[" + row[1] + "]", row[2]);
        }
        System.out.println("==============================================");
    }

    /** 思考模式对比：同一命令分别以 关/开 思考模式各调一次，观察耗时与输出差异 */
    private static void runThinkingCompare(SessionState st, HoneypotConfig config) {
        HoneypotConfig.Ai base = config.getAi();
        System.out.println("\n--- 思考模式对比（enable_thinking 关 vs 开）---");
        String cmd = "./setup -p 8888";
        for (boolean on : new boolean[]{false, true}) {
            HoneypotConfig.Ai cfg = copyAi(base);
            cfg.setEnable_thinking(on);
            try (AiClient client = AiClient.create(cfg)) {
                if (client == null) { System.out.println("AI 未启用，跳过对比"); return; }
                long t0 = System.nanoTime();
                String out = client.generateShellOutput(st.hostname, st.username, st.cwd, List.of(), cmd);
                long ms = (System.nanoTime() - t0) / 1_000_000;
                System.out.println("\n[思考=" + (on ? "开" : "关") + "] 耗时 " + ms + "ms");
                printOutput(cmd, out == null ? "(null: 已降级)" : out);
            }
        }
    }

    private static String[] runOne(CommandProcessor processor, SessionState st,
                                   int idx, int total, String cmd, String expect) {
        System.out.println("\n--- 场景 " + idx + "/" + total + "  [预期: " + expect + "] ---");
        long t0 = System.nanoTime();
        String out = processor.execute(st, cmd);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        printOutput(cmd, out);
        return new String[]{cmd, expect, ms + "ms"};
    }

    private static void printOutput(String cmd, String out) {
        System.out.println("$ " + cmd);
        System.out.println("--------------------------------------------------");
        if (out == null || out.isBlank()) {
            System.out.println("(无输出)");
        } else {
            System.out.print(out.endsWith("\n") ? out : out + "\n");
        }
        System.out.println("--------------------------------------------------");
    }

    /** 构造服务不可达的 AI 配置：127.0.0.1:9（discard 端口）本机连接立即被拒 */
    private static HoneypotConfig.Ai deadConfig() {
        HoneypotConfig.Ai cfg = new HoneypotConfig.Ai();
        cfg.setEnabled(true);
        cfg.setBase_url("http://127.0.0.1:9");
        cfg.setModel_name("2B");
        cfg.setTimeout_seconds(5);
        return cfg;
    }

    private static HoneypotConfig.Ai copyAi(HoneypotConfig.Ai src) {
        HoneypotConfig.Ai cfg = new HoneypotConfig.Ai();
        cfg.setEnabled(src.isEnabled());
        cfg.setBase_url(src.getBase_url());
        cfg.setApi_key(src.getApi_key());
        cfg.setModel_name(src.getModel_name());
        cfg.setEnable_thinking(src.isEnable_thinking());
        cfg.setTimeout_seconds(src.getTimeout_seconds());
        cfg.setMax_output_chars(src.getMax_output_chars());
        cfg.setMax_concurrent(src.getMax_concurrent());
        cfg.setFailure_threshold(src.getFailure_threshold());
        cfg.setCooldown_seconds(src.getCooldown_seconds());
        return cfg;
    }

    /* ------------------------------------------------------------------ */
    /* 交互模式：模拟攻击者实时输入                                          */
    /* ------------------------------------------------------------------ */

    private static void runInteractive(CommandProcessor processor, SessionState st) throws Exception {
        System.out.println("模拟攻击者 root 从 " + ATTACKER_IP + " 登录，输入命令实时观察输出");
        System.out.println("已知命令走本地硬编码，未知命令交大模型仿真；exit/quit/Ctrl+Z 回车退出");
        System.out.println("==================================================");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        while (true) {
            System.out.print(st.prompt());
            System.out.flush();
            String line = in.readLine();
            if (line == null) break; // EOF（Ctrl+Z/Ctrl+D）
            line = line.trim();
            if (line.isEmpty()) continue;
            if (line.equals("exit") || line.equals("quit") || line.equals("logout")) break;
            String out = processor.execute(st, line);
            if (CommandProcessor.EXIT_SIGNAL.equals(out)) {
                System.out.println("logout（连接关闭）");
                break;
            }
            if (!out.isEmpty()) System.out.print(out.endsWith("\n") ? out : out + "\n");
        }
    }
}
