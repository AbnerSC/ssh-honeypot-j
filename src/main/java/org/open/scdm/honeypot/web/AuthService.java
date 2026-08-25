package org.open.scdm.honeypot.web;

import io.javalin.http.Context;
import io.javalin.http.UnauthorizedResponse;

import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Web 控制台认证服务：登录校验、服务端会话管理与登录失败防护。
 * <p>
 * 会话信息存于 Servlet Session（HttpOnly Cookie 承载），登录态校验统一经
 * {@link #requireUser(Context)} / {@link #requireAdmin(Context)} 入口。
 * 登录失败按来源 IP 计数锁定（内存级），减缓在线爆破。
 */
public class AuthService {

    private static final Logger LOG = Logger.getLogger(AuthService.class.getName());

    /** 登录失败锁定阈值：达到次数后锁定来源 IP */
    private static final int MAX_ATTEMPTS = 5;
    /** 登录失败锁定时长（毫秒） */
    private static final long LOCK_MILLIS = 15 * 60 * 1000L;
    /** 失败记录表容量上限：超限后不再为无记录的新 IP 计数，防伪造海量来源 IP 撑爆内存 */
    private static final int MAX_FAILURE_RECORDS = 65536;
    /** 过期失败记录惰性清理的最小间隔（毫秒）：仅在登录失败路径触发，无需后台线程 */
    private static final long CLEANUP_INTERVAL_MILLIS = 5 * 60 * 1000L;

    private final UserRepository users;
    /** 来源 IP -> 登录失败记录（仅内存，重启清零，对管理端爆破防护足够） */
    private final ConcurrentHashMap<String, long[]> failures = new ConcurrentHashMap<>();
    /** 上次失败记录清理时间戳（毫秒），配合惰性清理使用 */
    private final AtomicLong lastCleanupMillis = new AtomicLong(System.currentTimeMillis());

    public AuthService(UserRepository users) {
        this.users = users;
    }

    /**
     * 校验用户名/口令。成功返回用户信息（不含哈希）并记录登录时间；
     * 失败返回错误描述（IP 锁定 / 用户名或密码错误）。
     */
    public Map<String, Object> login(String ip, String username, String password) throws SQLException {
        long[] rec = failures.get(ip);
        if (rec != null && rec[0] >= MAX_ATTEMPTS) {
            if (System.currentTimeMillis() < rec[1]) {
                long mins = (rec[1] - System.currentTimeMillis() + 59_999) / 60_000;
                return Map.of("ok", false, "error", "连续登录失败次数过多，该来源 IP 已锁定，请 " + mins + " 分钟后重试");
            }
            failures.remove(ip);
        }
        Map<String, Object> user = (username == null) ? null : users.findByUsername(username.trim());
        boolean ok = user != null
                && Boolean.TRUE.equals(user.get("enabled"))
                && UserRepository.Passwords.verify(password == null ? "" : password,
                        (String) user.get("passwordHash"));
        if (!ok) {
            recordFailure(ip);
            LOG.warning("Web 控制台登录失败: ip=" + ip + " user=" + username);
            return Map.of("ok", false, "error", "用户名或密码错误");
        }
        failures.remove(ip);
        users.recordLogin(((Number) user.get("id")).longValue());
        user.remove("passwordHash");
        return Map.of("ok", true, "user", user);
    }

    /** 记录一次登录失败：计数 +1 或开启新窗口；表满时仅对已有记录的 IP 继续计数 */
    private void recordFailure(String ip) {
        if (failures.get(ip) == null && failures.mappingCount() >= MAX_FAILURE_RECORDS) {
            return; // 记录表已满且无该 IP 条目：放弃计数，仅影响锁定精度，不影响认证正确性
        }
        failures.compute(ip, (k, old) -> {
            long now = System.currentTimeMillis();
            if (old == null || now >= old[1]) return new long[]{1, now + LOCK_MILLIS};
            return new long[]{old[0] + 1, old[1]};
        });
        cleanupExpired();
    }

    /** 惰性清理：间隔内至多执行一次，移除已过锁定窗口的失败记录，防长期运行内存无限增长 */
    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        long prev = lastCleanupMillis.get();
        if (now - prev < CLEANUP_INTERVAL_MILLIS || !lastCleanupMillis.compareAndSet(prev, now)) {
            return;
        }
        failures.entrySet().removeIf(e -> now >= e.getValue()[1]);
    }

    /** 登录成功时写入会话（会话不存在时先创建；已存在则换 ID 防会话固定攻击）。
     *  注：直接经 Servlet Session API 以 Object 存取，避免 Javalin 泛型读取与 Jetty
     *  会话管理器内部类型（char[]）不兼容导致 ClassCastException */
    public static void establishSession(Context ctx, Map<String, Object> user) {
        var req = ctx.req();
        if (req.getSession(false) != null) {
            req.changeSessionId();
        } else {
            req.getSession(true);
        }
        var session = req.getSession(false);
        session.setAttribute("uid", String.valueOf(user.get("id")));
        session.setAttribute("uname", String.valueOf(user.get("username")));
        session.setAttribute("role", String.valueOf(user.get("role")));
    }

    public static void destroySession(Context ctx) {
        var session = ctx.req().getSession(false);
        if (session != null) session.invalidate();
    }

    /** 当前登录用户简要信息；未登录返回 null（直接读 Servlet Session，规避 Javalin 泛型转换问题） */
    public static Map<String, Object> currentUser(Context ctx) {
        var session = ctx.req().getSession(false);
        if (session == null) return null;
        Object uid = session.getAttribute("uid");
        if (uid == null) return null;
        return Map.of("id", Long.parseLong(String.valueOf(uid)),
                "username", String.valueOf(session.getAttribute("uname")),
                "role", String.valueOf(session.getAttribute("role")));
    }

    /** 要求已登录，否则抛 401 */
    public static Map<String, Object> requireUser(Context ctx) {
        Map<String, Object> user = currentUser(ctx);
        if (user == null) throw new UnauthorizedResponse("未登录或会话已过期");
        return user;
    }

    /** 要求管理员角色，否则抛 401（由全局异常处理转为 403） */
    public static Map<String, Object> requireAdmin(Context ctx) {
        Map<String, Object> user = requireUser(ctx);
        if (!UserRepository.ROLE_ADMIN.equals(user.get("role"))) {
            throw new ForbiddenResponse("仅管理员可执行该操作");
        }
        return user;
    }

    /** 权限不足异常，映射 HTTP 403 */
    public static class ForbiddenResponse extends RuntimeException {
        public ForbiddenResponse(String message) {
            super(message);
        }
    }
}
