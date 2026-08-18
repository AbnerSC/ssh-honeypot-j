package org.open.scdm.honeypot.web;

import com.google.gson.Gson;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpResponseException;
import io.javalin.http.UnauthorizedResponse;
import io.javalin.http.staticfiles.Location;
import io.javalin.json.JsonMapper;
import io.javalin.router.JavalinDefaultRoutingApi;
import org.open.scdm.honeypot.geo.IpLocator;

import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Web 可视化控制台服务器：Javalin（Jetty）内嵌部署，前端静态页与 API 同 jar 打包。
 * <p>
 * 静态资源位于 classpath /web（shade 进 fat-jar，离线可用）；
 * ECharts 图表库取自 WebJar，经 /api/vendor/echarts.js 输出，屏蔽版本号依赖。
 * <p>
 * 安全策略：除登录接口与登录页资源外全部要求登录（服务端 Session）；
 * 未登录访问 API 返回 401 JSON，访问页面重定向到登录页。
 */
public class WebServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(WebServer.class.getName());

    private final Javalin app;
    private final LogRepository logRepo;
    private final UserRepository userRepo;
    private final AuditLogRepository auditRepo;
    private final String echartsJs;

    /**
     * 启动 Web 控制台。失败不影响蜜罐主服务（仅告警并返回 null）。
     */
    public static WebServer start(int port, int sessionTimeoutMinutes, Path dbFile, IpLocator ipLocator) {
        try {
            WebServer server = new WebServer(sessionTimeoutMinutes, dbFile, ipLocator);
            server.app.start(port);
            LOG.info("Web 控制台已启动: http://<host>:" + port + "/ （默认管理员 admin/admin123，首次登录强制改密）");
            return server;
        } catch (Exception e) {
            LOG.severe("Web 控制台启动失败，蜜罐服务继续运行: " + e.getMessage());
            return null;
        }
    }

    private WebServer(int sessionTimeoutMinutes, Path dbFile, IpLocator ipLocator) throws Exception {
        this.logRepo = new LogRepository(dbFile);
        this.userRepo = new UserRepository(dbFile);
        this.auditRepo = new AuditLogRepository(dbFile, ipLocator);
        AuthService auth = new AuthService(userRepo);
        this.echartsJs = loadEcharts();

        Gson gson = new Gson();
        // Javalin 7：路由/前置拦截/异常处理器必须在创建时（config.routes）前置注册
        this.app = Javalin.create(config -> {
            // 前端页面（随 jar 打包）；HTML/JS/CSS 禁用缓存，确保升级与改密等
            // 状态变更后浏览器始终加载最新版本，不会因旧缓存导致界面状态不一致
            config.staticFiles.add(sf -> {
                sf.directory = "/web";
                sf.location = Location.CLASSPATH;
                sf.headers = Map.of("Cache-Control", "no-cache, no-store, must-revalidate");
            });
            config.jsonMapper(new JsonMapper() {  // JSON 序列化统一走 Gson
                @Override
                public String toJsonString(Object obj, Type type) {
                    return gson.toJson(obj, type);
                }

                @Override
                public <T> T fromJsonString(String json, Type targetType) {
                    return gson.fromJson(json, targetType);
                }
            });
            // 压缩策略用 Javalin 默认（gzip/brotli，超过阈值才压缩），ECharts 等大资源自动受益
            try {
                // Jetty 12：ServletContextHandler 位于 ee10.servlet 包
                config.jetty.modifyServletContextHandler(sc ->
                        sc.getSessionHandler().setMaxInactiveInterval(sessionTimeoutMinutes * 60));
            } catch (Exception ignored) {
                // 会话超时设置失败时退回 Jetty 默认值，不影响启动
            }

            JavalinDefaultRoutingApi routes = config.routes;
            // 审计中间件：before 记录起始时间与请求体，after 落库（Javalin 7 中 after 先于 before 执行）
            routes.before(ctx -> {
                String p = ctx.path();
                if (p.startsWith("/api/") && !p.startsWith("/api/vendor/")) {
                    ctx.attribute("auditStart", System.currentTimeMillis());
                    try {
                        ctx.attribute("auditReqBody", ctx.body());
                    } catch (Exception ignored) {
                    }
                }
            });
            routes.before(this::authGuard);
            routes.after(this::auditMiddleware);

            // 统一异常输出为 JSON；未登录访问页面时重定向到登录页
            routes.exception(UnauthorizedResponse.class, (e, ctx) -> {
                if (ctx.path().startsWith("/api/")) {
                    ctx.status(401);
                    ctx.json(Map.of("ok", false, "error", e.getMessage()));
                } else {
                    ctx.redirect("/login.html");
                }
            });
            routes.exception(AuthService.ForbiddenResponse.class, (e, ctx) -> {
                ctx.status(403);
                ctx.json(Map.of("ok", false, "error", e.getMessage()));
            });
            routes.exception(HttpResponseException.class, (e, ctx) -> {
                ctx.status(e.getStatus());
                ctx.json(Map.of("ok", false, "error", e.getMessage()));
            });
            routes.exception(Exception.class, (e, ctx) -> {
                java.io.StringWriter sw = new java.io.StringWriter();
                e.printStackTrace(new java.io.PrintWriter(sw));
                LOG.warning("Web 请求处理失败: " + ctx.method() + " " + ctx.path() + " -> " + sw);
                ctx.status(500);
                ctx.json(Map.of("ok", false, "error", "服务器内部错误"));
            });

            new ApiController(logRepo, userRepo, auth, auditRepo).register(routes);

            // ECharts 图表库：从 WebJar 类路径加载一次，长期驻留内存输出
            routes.get("/api/vendor/echarts.js", ctx ->
                    ctx.contentType("application/javascript; charset=utf-8").result(echartsJs));
        });
    }

    /**
     * 登录守卫：登录接口与登录页静态资源放行，其余请求一律要求有效会话。
     */
    private void authGuard(Context ctx) {
        String path = ctx.path();
        if (path.startsWith("/api/login")) return;
        boolean isApi = path.startsWith("/api/");
        boolean publicStatic = !isApi && (path.equals("/login.html")
                || path.startsWith("/css/") || path.startsWith("/js/"));
        if (isApi || !publicStatic) {
            if (AuthService.currentUser(ctx) == null) {
                throw new UnauthorizedResponse("未登录或会话已过期");
            }
        }
    }

    /** 审计中间件（after）：读取 before 阶段存入的请求起始时间与请求体，响应完成后落库 */
    private void auditMiddleware(Context ctx) {
        String path = ctx.path();
        if (!path.startsWith("/api/") || path.startsWith("/api/vendor/")) {
            return;
        }
        Long startAttr = ctx.attribute("auditStart");
        if (startAttr == null) return;
        long duration = System.currentTimeMillis() - startAttr;
        String reqBody = ctx.attribute("auditReqBody");

        int status = ctx.statusCode();
        boolean ok = status < 400;

        String username = null;
        Map<String, Object> session = AuthService.currentUser(ctx);
        if (session != null) {
            username = (String) session.get("username");
        }

        // 响应体摘要：成功记 {"ok":true}，失败记状态码，避免存储大列表
        String respBody = ok ? "{\"ok\":true}" : "{\"ok\":false,\"status\":" + status + "}";

        auditRepo.record(
                username,
                ClientIps.resolve(ctx),
                ctx.method().name(),
                path,
                ctx.queryString(),
                AuditLogRepository.maskBody(reqBody),
                status,
                respBody,
                duration,
                ok
        );
    }

    /**
     * 从 WebJar 类路径加载 echarts.min.js（仅加载一次）。
     * 经 WebJar 自带的 maven pom.properties 读取实际版本号，避免硬编码版本目录；
     * 兼容 IDE 开发目录与 shade fat-jar 两种运行形态。
     */
    private static String loadEcharts() throws Exception {
        var loader = WebServer.class.getClassLoader();
        try (InputStream meta = loader.getResourceAsStream("META-INF/maven/org.webjars.npm/echarts/pom.properties")) {
            if (meta != null) {
                Properties props = new Properties();
                props.load(meta);
                String version = props.getProperty("version");
                if (version != null) {
                    String resource = "META-INF/resources/webjars/echarts/" + version + "/dist/echarts.min.js";
                    try (InputStream in = loader.getResourceAsStream(resource)) {
                        if (in != null) {
                            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
                        }
                    }
                }
            }
        }
        throw new IllegalStateException("未找到 ECharts WebJar 资源（org.webjars.npm:echarts 依赖缺失？）");
    }

    public void stop() {
        close();
    }

    @Override
    public void close() {
        try {
            app.stop();
        } catch (Exception ignored) {
        }
        try {
            logRepo.close();
        } catch (Exception ignored) {
        }
        try {
            userRepo.close();
        } catch (Exception ignored) {
        }
        try {
            auditRepo.close();
        } catch (Exception ignored) {
        }
    }
}
