package org.open.scdm.honeypot.web;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.NotFoundResponse;
import io.javalin.http.UnauthorizedResponse;
import io.javalin.router.JavalinDefaultRoutingApi;

import java.lang.reflect.Type;
import java.util.Map;

/**
 * Web 控制台 REST API：登录认证、统计总览、各事件明细分页查询、系统用户管理。
 * <p>
 * 响应约定：成功 {"ok":true,"data":...}；失败 {"ok":false,"error":"..."} + 对应 HTTP 状态码。
 * 所有接口均要求已登录（登录接口除外），用户管理类接口额外要求 admin 角色。
 */
public class ApiController {

    private static final Gson GSON = new Gson();
    /** 请求体 JSON 反序列化目标类型：只构建一次，避免每次解析分配匿名 TypeToken 子类 */
    private static final Type BODY_TYPE = new TypeToken<Map<String, Object>>() {}.getType();

    private final LogRepository logs;
    private final UserRepository users;
    private final AuthService auth;
    private final AuditLogRepository audit;

    public ApiController(LogRepository logs, UserRepository users, AuthService auth, AuditLogRepository audit) {
        this.logs = logs;
        this.users = users;
        this.auth = auth;
        this.audit = audit;
    }

    /** Javalin 7：路由改为在 Javalin.create 配置块内前置注册 */
    public void register(JavalinDefaultRoutingApi app) {
        // ---------- 认证 ----------
        app.post("/api/login", this::login);
        app.post("/api/logout", ctx -> {
            AuthService.destroySession(ctx);
            ctx.json(Map.of("ok", true));
        });
        app.get("/api/me", this::me);
        app.put("/api/password", this::changePassword);

        // ---------- 攻击日志统计 ----------
        app.get("/api/stats/overview", ctx -> ok(ctx, logs.overview()));
        app.get("/api/stats/trend", ctx -> ok(ctx, logs.trend(daysParam(ctx))));
        app.get("/api/stats/protocol", ctx -> ok(ctx, logs.protocolDist()));
        app.get("/api/stats/top-ips", ctx -> ok(ctx, logs.topIps(limitParam(ctx))));
        app.get("/api/stats/top-locations", ctx -> ok(ctx, logs.topLocations(limitParam(ctx))));
        app.get("/api/stats/top-usernames", ctx -> ok(ctx, logs.topUsernames(limitParam(ctx))));
        app.get("/api/stats/top-passwords", ctx -> ok(ctx, logs.topPasswords(limitParam(ctx))));

        // ---------- 攻击日志明细（分页 + 过滤） ----------
        app.get("/api/sessions", ctx -> ok(ctx, logs.sessions(
                ctx.queryParam("srcIp"), ctx.queryParam("protocol"),
                longParam(ctx, "start"), longParam(ctx, "end"), page(ctx), size(ctx))));
        app.get("/api/auth-attempts", ctx -> ok(ctx, logs.authAttempts(
                ctx.queryParam("srcIp"), ctx.queryParam("username"), ctx.queryParam("protocol"),
                boolParam(ctx, "success"), longParam(ctx, "start"), longParam(ctx, "end"), page(ctx), size(ctx))));
        app.get("/api/commands", ctx -> ok(ctx, logs.commands(
                ctx.queryParam("sessionId"),
                ctx.queryParam("srcIp"), ctx.queryParam("username"), ctx.queryParam("keyword"),
                longParam(ctx, "start"), longParam(ctx, "end"), page(ctx), size(ctx))));
        app.get("/api/downloads", ctx -> ok(ctx, logs.downloads(
                ctx.queryParam("srcIp"), ctx.queryParam("keyword"),
                longParam(ctx, "start"), longParam(ctx, "end"), page(ctx), size(ctx))));
        app.get("/api/ip-locks", ctx -> ok(ctx, logs.ipLocks(ctx.queryParam("srcIp"), page(ctx), size(ctx))));

        // ---------- 系统操作审计日志（仅 admin） ----------
        app.get("/api/audit-logs", ctx -> {
            AuthService.requireAdmin(ctx);
            ok(ctx, audit.list(
                    ctx.queryParam("username"), ctx.queryParam("srcIp"),
                    ctx.queryParam("method"), ctx.queryParam("path"),
                    longParam(ctx, "start"), longParam(ctx, "end"), page(ctx), size(ctx)));
        });
        app.get("/api/audit-logs/trend", ctx -> {
            AuthService.requireAdmin(ctx);
            ok(ctx, audit.trend(daysParam(ctx)));
        });

        // ---------- 系统用户管理（仅 admin） ----------
        app.get("/api/users", ctx -> {
            AuthService.requireAdmin(ctx);
            ok(ctx, users.listUsers());
        });
        app.post("/api/users", this::userCreate);
        app.put("/api/users/{id}/status", this::userUpdateStatus);
        app.put("/api/users/{id}/password", this::userResetPassword);
        app.delete("/api/users/{id}", this::userDelete);
    }

    // ============================ 认证相关 ============================

    private void login(Context ctx) throws Exception {
        Map<String, Object> body = body(ctx);
        String username = str(body.get("username"));
        String password = str(body.get("password"));
        if (username.isEmpty() || password.isEmpty()) throw new BadRequestResponse("请输入用户名和密码");
        Map<String, Object> result = auth.login(ClientIps.resolve(ctx), username, password);
        if (Boolean.TRUE.equals(result.get("ok"))) {
            @SuppressWarnings("unchecked")
            Map<String, Object> user = (Map<String, Object>) result.get("user");
            AuthService.establishSession(ctx, user);
            ctx.json(Map.of("ok", true, "user", user));
        } else {
            ctx.status(401);
            ctx.json(result);
        }
    }

    private void me(Context ctx) throws Exception {
        Map<String, Object> session = AuthService.requireUser(ctx);
        Map<String, Object> user = users.findById(((Number) session.get("id")).longValue());
        if (user == null || !Boolean.TRUE.equals(user.get("enabled"))) {
            AuthService.destroySession(ctx); // 账号已删除/禁用，清除残留会话
            throw new UnauthorizedResponse("账号不可用");
        }
        ctx.json(Map.of("ok", true, "user", user));
    }

    private void changePassword(Context ctx) throws Exception {
        Map<String, Object> session = AuthService.requireUser(ctx);
        Map<String, Object> body = body(ctx);
        String oldPwd = str(body.get("oldPassword"));
        String newPwd = str(body.get("newPassword"));
        validatePassword(newPwd);
        Map<String, Object> dbUser = users.findByUsername((String) session.get("username"));
        if (dbUser == null || !UserRepository.Passwords.verify(oldPwd, (String) dbUser.get("passwordHash"))) {
            throw new BadRequestResponse("原密码错误");
        }
        users.changePassword(((Number) session.get("id")).longValue(), newPwd);
        ctx.json(Map.of("ok", true));
    }

    // ============================ 用户管理 ============================

    private void userCreate(Context ctx) throws Exception {
        AuthService.requireAdmin(ctx);
        Map<String, Object> body = body(ctx);
        String username = str(body.get("username"));
        String password = str(body.get("password"));
        String role = str(body.get("role"));
        validateUsername(username);
        validatePassword(password);
        validateRole(role);
        if (users.findByUsername(username) != null) throw new BadRequestResponse("用户名已存在");
        boolean mustChange = body.get("mustChange") instanceof Boolean b ? b : true;
        long id = users.createUser(username, password, role, mustChange);
        ctx.status(201);
        ctx.json(Map.of("ok", true, "data", Map.of("id", id)));
    }

    private void userUpdateStatus(Context ctx) throws Exception {
        Map<String, Object> self = AuthService.requireAdmin(ctx);
        long targetId = ctx.pathParamAsClass("id", Long.class).required().get();
        Map<String, Object> body = body(ctx);
        if (!(body.get("enabled") instanceof Boolean enabled)) throw new BadRequestResponse("参数 enabled 缺失");
        Map<String, Object> target = users.findById(targetId);
        if (target == null) throw new NotFoundResponse("用户不存在");
        if (!enabled && UserRepository.ROLE_ADMIN.equals(target.get("role"))) {
            if (targetId == ((Number) self.get("id")).longValue()) throw new BadRequestResponse("不能禁用当前登录账号");
            if (users.countAdmins() <= 1) throw new BadRequestResponse("至少保留一个启用状态的管理员");
        }
        users.setStatus(targetId, enabled);
        ctx.json(Map.of("ok", true));
    }

    private void userResetPassword(Context ctx) throws Exception {
        AuthService.requireAdmin(ctx);
        long targetId = ctx.pathParamAsClass("id", Long.class).required().get();
        Map<String, Object> body = body(ctx);
        String password = str(body.get("password"));
        validatePassword(password);
        if (users.findById(targetId) == null) throw new NotFoundResponse("用户不存在");
        boolean mustChange = body.get("mustChange") instanceof Boolean b ? b : true;
        users.resetPassword(targetId, password, mustChange);
        ctx.json(Map.of("ok", true));
    }

    private void userDelete(Context ctx) throws Exception {
        Map<String, Object> self = AuthService.requireAdmin(ctx);
        long targetId = ctx.pathParamAsClass("id", Long.class).required().get();
        if (targetId == ((Number) self.get("id")).longValue()) throw new BadRequestResponse("不能删除当前登录账号");
        Map<String, Object> target = users.findById(targetId);
        if (target == null) throw new NotFoundResponse("用户不存在");
        if (UserRepository.ROLE_ADMIN.equals(target.get("role")) && users.countAdmins() <= 1) {
            throw new BadRequestResponse("至少保留一个启用状态的管理员");
        }
        users.deleteUser(targetId);
        ctx.json(Map.of("ok", true));
    }

    // ============================ 工具方法 ============================

    private static void ok(Context ctx, Object data) {
        ctx.json(Map.of("ok", true, "data", data));
    }

    private static Map<String, Object> body(Context ctx) {
        try {
            Map<String, Object> m = GSON.fromJson(ctx.body(), BODY_TYPE);
            return m == null ? Map.of() : m;
        } catch (Exception e) {
            throw new BadRequestResponse("请求体不是合法 JSON");
        }
    }

    private static void validateUsername(String username) {
        if (!username.matches("[a-zA-Z0-9_.-]{2,32}")) {
            throw new BadRequestResponse("用户名仅允许字母、数字、下划线、点、短横线，长度 2-32");
        }
    }

    private static void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw new BadRequestResponse("密码长度至少 8 位");
        }
    }

    private static void validateRole(String role) {
        if (!UserRepository.ROLE_ADMIN.equals(role) && !UserRepository.ROLE_VIEWER.equals(role)) {
            throw new BadRequestResponse("角色非法，仅支持 admin / viewer");
        }
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o).trim();
    }

    private static int page(Context ctx) {
        return Math.max(1, intParam(ctx, "page", 1));
    }

    private static int size(Context ctx) {
        return Math.min(200, Math.max(1, intParam(ctx, "size", 20)));
    }

    private static int limitParam(Context ctx) {
        return Math.min(50, Math.max(1, intParam(ctx, "limit", 10)));
    }

    private static int daysParam(Context ctx) {
        return Math.min(30, Math.max(1, intParam(ctx, "days", 14)));
    }

    private static int intParam(Context ctx, String name, int def) {
        String v = ctx.queryParam(name);
        if (v == null || v.isBlank()) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static Long longParam(Context ctx, String name) {
        String v = ctx.queryParam(name);
        if (v == null || v.isBlank()) return null;
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Boolean boolParam(Context ctx, String name) {
        String v = ctx.queryParam(name);
        if (v == null || v.isBlank()) return null;
        return "1".equals(v) || "true".equalsIgnoreCase(v);
    }
}
