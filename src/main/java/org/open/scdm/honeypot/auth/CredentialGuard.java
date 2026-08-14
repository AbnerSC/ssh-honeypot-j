package org.open.scdm.honeypot.auth;

import org.open.scdm.honeypot.log.AttackLogger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * 凭证守卫：基于内存密码本校验登录凭证，并对连续失败的源 IP 实施临时锁定。
 * <p>
 * 规则：
 *  - 只有密码本中的 用户名/密码 组合才允许登录成功，不再全部放行
 *  - 每个账号可配置多个密码，命中任意一个即视为登录成功
 *  - 同一源 IP 在可配置时间窗口（默认 5 分钟）内连续登录失败达到阈值（默认 3 次）后锁定；
 *    若两次失败间隔超过窗口，则失败计数重置，不再累计
 *  - 登录成功会清零该 IP 的失败计数
 *  - 失败计数与锁定状态全部缓存在内存中，进程重启后清空
 */
public class CredentialGuard {
    private static final Logger LOG = Logger.getLogger(CredentialGuard.class.getName());

    private final Map<String, List<String>> credentials;   // 密码本：用户名 -> 密码列表
    private final int maxFailures;                   // 连续失败达到该次数即锁定
    private final long windowMillis;                 // 失败计数窗口（毫秒）
    private final long lockMillis;                   // 锁定时长（毫秒）
    private final AttackLogger logger;

    /** IP -> 连续失败次数（内存缓存） */
    private final Map<String, Integer> failCounts = new ConcurrentHashMap<>();
    /** IP -> 最近一次失败时间戳（毫秒，内存缓存），用于判断窗口是否过期 */
    private final Map<String, Long> lastFailAt = new ConcurrentHashMap<>();
    /** IP -> 锁定截止时间戳（毫秒，内存缓存） */
    private final Map<String, Long> lockedUntil = new ConcurrentHashMap<>();

    public CredentialGuard(Map<String, List<String>> credentials, int maxFailures,
                           int windowMinutes, int lockMinutes, AttackLogger logger) {
        Map<String, List<String>> normalized = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : credentials.entrySet()) {
            List<String> ps = e.getValue() == null ? List.of() : e.getValue();
            normalized.put(e.getKey(), List.copyOf(ps));
        }
        this.credentials = Map.copyOf(normalized);
        this.maxFailures = Math.max(1, maxFailures);
        this.windowMillis = Math.max(1, windowMinutes) * 60_000L;
        this.lockMillis = Math.max(1, lockMinutes) * 60_000L;
        this.logger = logger;
        int pwdCount = credentials.values().stream().mapToInt(l -> l == null ? 0 : l.size()).sum();
        LOG.info("密码本已加载，共 " + credentials.size() + " 个账号、" + pwdCount + " 条密码；" +
                windowMinutes + " 分钟内连续失败 " + this.maxFailures + " 次锁定 " + lockMinutes + " 分钟");
    }

    /** 该 IP 是否处于锁定状态（锁定过期自动解除） */
    public boolean isLocked(String ip) {
        Long until = lockedUntil.get(ip);
        if (until == null) return false;
        if (System.currentTimeMillis() >= until) {
            lockedUntil.remove(ip, until);
            failCounts.remove(ip);
            lastFailAt.remove(ip);
            return false;
        }
        return true;
    }

    /**
     * 校验登录凭证并维护失败计数。
     * 已锁定的 IP 直接拒绝；窗口外的失败会重置计数，窗口内累计失败达到阈值后立即锁定并记录 ip_locked 事件。
     */
    public synchronized boolean authenticate(String ip, String username, String password) {
        if (isLocked(ip)) return false;
        List<String> expectedList = username == null ? null : credentials.get(username);
        String pwd = password == null ? "" : password;
        boolean ok = expectedList != null && expectedList.contains(pwd);
        if (ok) {
            failCounts.remove(ip);
            lastFailAt.remove(ip);
        } else {
            long now = System.currentTimeMillis();
            Long prev = lastFailAt.get(ip);
            // 距上次失败已超过窗口，则视为新的一轮，重置计数
            if (prev != null && now - prev > windowMillis) {
                failCounts.remove(ip);
            }
            int n = failCounts.merge(ip, 1, Integer::sum);
            lastFailAt.put(ip, now);
            if (n >= maxFailures) {
                long until = now + lockMillis;
                lockedUntil.put(ip, until);
                failCounts.remove(ip);
                lastFailAt.remove(ip);
                LOG.warning("源 IP " + ip + " 在 " + (windowMillis / 60_000) + " 分钟内连续登录失败 " +
                        n + " 次，锁定 " + (lockMillis / 60_000) + " 分钟");
                if (logger != null) logger.ipLocked(ip, until);
            }
        }
        return ok;
    }

    /** 连续失败阈值（Telnet 侧用作单连接允许的最大尝试次数） */
    public int getMaxFailures() {
        return maxFailures;
    }
}
