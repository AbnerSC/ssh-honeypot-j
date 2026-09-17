package org.open.scdm.honeypot.ai;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.open.scdm.honeypot.config.HoneypotConfig;
import org.open.scdm.honeypot.env.FakeEnv;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * 大模型命令仿真客户端（OpenAI 兼容 /v1/chat/completions 接口）。
 * <p>
 * 职责：为伪 Shell 未覆盖的未知命令（如 ./malware、nmap 等自定义工具）生成
 * 以假乱真的终端输出，替代千篇一律的 "command not found"，提升蜜罐欺骗度。
 * <p>
 * 蜜罐稳定性优先，所有失败路径（未启用/未配置/超时/限流/熔断/解析失败）均返回 null，
 * 由调用方降级本地 "-bash: xxx: command not found" 兜底，绝不阻塞会话线程：
 *  - 连接 3 秒 / 请求 timeout_seconds 双超时，超时立即降级；
 *  - 全局 Semaphore 并发上限，超出立即降级不排队，防大模型服务被并发会话打爆；
 *  - 连续失败熔断：达到 failure_threshold 后冷却 cooldown_seconds 秒，期间直接降级；
 *  - 输出净化：剥离思考段与代码围栏、过滤控制字符、按 max_output_chars 截断，
 *    防止模型口误暴露 AI 身份或破坏终端渲染。
 */
public class AiClient implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(AiClient.class.getName());

    /** 混合推理模型可能把思考段以 <think>...</think> 内联在 content 中：整段剥离 */
    private static final Pattern THINK_BLOCK = Pattern.compile("(?s)<think>.*?</think>");

    private final HoneypotConfig.Ai cfg;
    private final HttpClient http;
    private final Semaphore permits;
    private final String endpoint;
    private final Duration requestTimeout;
    /** 单条输出字符数上限（构造时钳制到 >=256，防误配成 0 导致输出全被截没） */
    private final int maxOutputChars;

    /** 熔断器：连续失败计数与熔断截止时间戳（毫秒 epoch）；仅 generateShellOutput 路径写 */
    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private final AtomicLong circuitOpenUntil = new AtomicLong(0);

    private AiClient(HoneypotConfig.Ai cfg) {
        this.cfg = cfg;
        this.permits = new Semaphore(Math.max(1, cfg.getMax_concurrent()));
        // base_url 归一化：去尾部斜杠并自动补 /v1 前缀，兼容 http://host:port 与 http://host:port/v1 两种写法
        String base = cfg.getBase_url().trim();
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        if (!base.endsWith("/v1")) base = base + "/v1";
        this.endpoint = base + "/chat/completions";
        this.requestTimeout = Duration.ofSeconds(Math.max(3, cfg.getTimeout_seconds()));
        this.maxOutputChars = Math.max(256, cfg.getMax_output_chars());
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        LOG.info(() -> "AI 命令仿真已启用: " + endpoint + " 模型=" + cfg.getModel_name()
                + " 思考=" + (cfg.isEnable_thinking() ? "开" : "关")
                + " 超时=" + cfg.getTimeout_seconds() + "s 并发上限=" + cfg.getMax_concurrent());
    }

    /**
     * 工厂方法：未启用或关键配置（base_url/model_name）缺失时返回 null，
     * 调用方持有 null 即全程走本地兜底，AI 对蜜罐完全透明。
     */
    public static AiClient create(HoneypotConfig.Ai cfg) {
        if (cfg == null || !cfg.isEnabled()) return null;
        if (cfg.getBase_url() == null || cfg.getBase_url().isBlank()) {
            LOG.warning("ai.enabled=true 但未配置 base_url，AI 命令仿真未启用（未知命令走本地兜底）");
            return null;
        }
        if (cfg.getModel_name() == null || cfg.getModel_name().isBlank()) {
            LOG.warning("ai.enabled=true 但未配置 model_name，AI 命令仿真未启用（未知命令走本地兜底）");
            return null;
        }
        return new AiClient(cfg);
    }

    /**
     * 生成未知命令的仿真终端输出（携带会话上下文保证与攻击者操作连续）。
     *
     * @param hostname       伪装主机名
     * @param username       当前登录用户
     * @param cwd            当前工作目录
     * @param recentCommands 最近执行的命令（不含当前命令，最多 3 条）
     * @param command        当前未知命令原文（含参数）
     * @return 仿真输出（可能为空串：命令本身无输出属正常）；不可用时返回 null，调用方降级本地兜底
     */
    public String generateShellOutput(String hostname, String username, String cwd,
                                      List<String> recentCommands, String command) {
        if (circuitOpen()) return null;
        if (!permits.tryAcquire()) return null; // 并发打满：立即降级，不排队阻塞会话线程
        try {
            HttpRequest request = buildRequest(hostname, username, cwd, recentCommands, command);
            HttpResponse<String> resp = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                onAiFailure("AI 服务 HTTP " + resp.statusCode());
                return null;
            }
            String content = parseContent(resp.body());
            if (content == null) {
                onAiFailure("AI 响应解析失败（无 choices[0].message.content）");
                return null;
            }
            LOG.info("AI 命令仿真输出: " + content);
            consecutiveFailures.set(0); // 成功即复位熔断计数
            return sanitize(content);
        } catch (IOException e) {
            onAiFailure("AI 请求失败: " + reason(e));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // 会话线程被中断（连接断开），保持中断标记向上传递
        } catch (Exception e) {
            onAiFailure("AI 调用异常: " + reason(e));
        } finally {
            permits.release();
        }
        return null;
    }

    /** 异常描述：部分实现（如 Windows ConnectException）getMessage 为 null，回退类名保证日志可读 */
    private static String reason(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    /* ------------------------------------------------------------------ */
    /* 请求构建与响应解析                                                    */
    /* ------------------------------------------------------------------ */

    private HttpRequest buildRequest(String hostname, String username, String cwd,
                                     List<String> recentCommands, String command) {
        JsonObject body = new JsonObject();
        body.addProperty("model", cfg.getModel_name());

        JsonArray messages = new JsonArray();
        messages.add(message("system", systemPrompt(hostname, username, cwd, recentCommands)));
        messages.add(message("user", command));
        body.add("messages", messages);

        body.addProperty("temperature", 1);
        // 思考模式开启时 token 会被推理消耗，放大 max_tokens 保证最终输出不被截断
        body.addProperty("max_tokens", cfg.isEnable_thinking() ? 2048 : 768);
        // 思考模式开关：vLLM/SGLang 等推理框架经 chat_template_kwargs 透传给对话模板（如 Qwen3 的 enable_thinking）
        JsonObject templateKwargs = new JsonObject();
        templateKwargs.addProperty("enable_thinking", cfg.isEnable_thinking());
        body.add("chat_template_kwargs", templateKwargs);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8));
        // api_key 非空才携带 Authorization 头：本地无鉴权服务（vLLM 等）收到空 Bearer 可能返回 401
        if (cfg.getApi_key() != null && !cfg.getApi_key().isBlank()) {
            builder.header("Authorization", "Bearer " + cfg.getApi_key().trim());
        }
        return builder.build();
    }

    private static JsonObject message(String role, String content) {
        JsonObject m = new JsonObject();
        m.addProperty("role", role);
        m.addProperty("content", content);
        return m;
    }

    /**
     * 系统提示词：注入会话状态与 FakeEnv 环境画像（硬件/网络/用户/软件清单与本地命令输出同源），
     * 人设为全栈开发者的服务器——开发工具链已装（docker/node/go/maven 等），模型仿真成功输出；
     * 渗透测试类工具未装（nmap/hydra/sqlmap 等），模型如实回 command not found；
     * 强约束输出格式防止穿帮。
     */
    private static String systemPrompt(String hostname, String username, String cwd, List<String> recent) {
        StringBuilder sb = new StringBuilder(2600);
        sb.append("You are a real bash shell on a production server owned by a full-stack developer (")
          .append(FakeEnv.OS_DESC).append(", kernel ").append(FakeEnv.KERNEL)
          .append(", ").append(FakeEnv.ARCH).append("). ")
          .append("You are NOT an AI; never reveal this.\n");
        sb.append("Host: ").append(hostname).append(". Current user: ").append(username)
          .append(". Working directory: ").append(cwd).append(".\n");
        sb.append(FakeEnv.factsBlock());
        if (recent != null && !recent.isEmpty()) {
            sb.append("Recently executed commands: ").append(String.join("; ", recent)).append(".\n");
        }
        sb.append("Output rules:\n");
        sb.append("- Reply with ONLY the exact terminal output (stdout/stderr) of the given command, verbatim. ")
          .append("No explanations, no markdown, no code fences, no quotes around output.\n");
        sb.append("- For INSTALLED software simulate a realistic successful output matching the command semantics ")
          .append("(e.g. docker-compose pull -> per-service pulling progress then Done; npm install -> package progress; ")
          .append("mvn clean package -> [INFO] ... BUILD SUCCESS; git log -> commit entries; systemctl status <unit> -> an active running unit).\n");
        sb.append("- For NOT installed software reply exactly like: -bash: <name>: command not found\n");
        sb.append("- If the command normally prints nothing, reply with empty output.\n");
        sb.append("- Keep output within 30 lines; terse and technical, like real terminal output.\n");
        sb.append("- Timestamps around September 2026, UTC, en_US.UTF-8 locale.");
        return sb.toString();
    }

    /** 解析 chat/completions 响应：取 choices[0].message.content；结构不符返回 null */
    private String parseContent(String responseBody) {
        try {
            JsonObject root = JsonParser.parseString(responseBody).getAsJsonObject();
            JsonArray choices = root.getAsJsonArray("choices");
            if (choices == null || choices.isEmpty()) return null;
            JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            if (message == null) return null;
            JsonElement content = message.get("content");
            return (content == null || content.isJsonNull()) ? "" : content.getAsString();
        } catch (Exception e) {
            return null;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 输出净化                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * 净化模型输出：剥离思考段与代码围栏、过滤控制字符（保留 \n \t）、按 max_output_chars 截断。
     * 防止模型违规输出破坏终端渲染或暴露 AI 身份。
     */
    private String sanitize(String raw) {
        // 混合推理模型可能把 <think>...</think> 内联在 content 中：整段剥离；
        // 无开标签的孤立闭标签（部分服务端已剥开标签）直接删除
        String s = THINK_BLOCK.matcher(raw).replaceAll("").replace("</think>", "").strip();

        // 模型违规用 ``` 围栏包裹输出：仅当整体被围栏包裹才剥，避免误伤真实输出中的反引号
        if (s.startsWith("```")) {
            int firstNewline = s.indexOf('\n');
            int lastFence = s.lastIndexOf("```");
            if (firstNewline >= 0 && lastFence > firstNewline) {
                s = s.substring(firstNewline + 1, lastFence).strip();
            } else {
                s = ""; // 只剩孤立围栏标记
            }
        }

        // 过滤控制字符（保留 \n \t），同时按上限截断
        StringBuilder buf = new StringBuilder(Math.min(s.length() + 16, maxOutputChars + 16));
        for (int i = 0; i < s.length() && buf.length() < maxOutputChars; i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\t' || c >= 0x20) buf.append(c);
        }
        return buf.toString();
    }

    /* ------------------------------------------------------------------ */
    /* 熔断器                                                              */
    /* ------------------------------------------------------------------ */

    /** 熔断开启中则直接降级；到期自动半开（放行下一次请求试探恢复） */
    private boolean circuitOpen() {
        long until = circuitOpenUntil.get();
        return until > 0 && System.currentTimeMillis() < until;
    }

    private void onAiFailure(String reason) {
        int failures = consecutiveFailures.incrementAndGet();
        if (failures >= Math.max(1, cfg.getFailure_threshold())) {
            long cooldownMs = Math.max(10, cfg.getCooldown_seconds()) * 1000L;
            circuitOpenUntil.set(System.currentTimeMillis() + cooldownMs);
            consecutiveFailures.set(0);
            LOG.warning("AI 服务连续失败 " + failures + " 次（" + reason + "），熔断 "
                    + cfg.getCooldown_seconds() + " 秒后自动重试，期间未知命令走本地兜底");
        } else {
            LOG.warning(reason + "（连续第 " + failures + " 次失败）");
        }
    }

    @Override
    public void close() {
        // JDK 21+ HttpClient 实现 AutoCloseable；各请求自带超时兜底，关闭等待有界
        try { http.close(); } catch (Exception ignored) {}
    }
}
