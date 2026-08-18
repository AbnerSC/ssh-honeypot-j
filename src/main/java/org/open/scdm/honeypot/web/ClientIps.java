package org.open.scdm.honeypot.web;

import io.javalin.http.Context;

/**
 * 客户端真实 IP 解析：经 nginx 等反向代理时 {@code ctx.ip()} 只能拿到代理的内网地址，
 * 需优先解析代理附加的转发头（X-Forwarded-For / X-Real-IP 等）。
 * <p>
 * 仅当直连地址为私网/环回（即判定存在本机前置代理）时才信任转发头，
 * 避免公网直连请求伪造 X-Forwarded-For 干扰审计与登录锁定。
 * 多级代理时取转发链首个合法公网 IP（链上全为内网时取首个内网 IP）。
 */
public final class ClientIps {

    /** 常见代理附加头，按优先级排列 */
    private static final String[] FORWARDED_HEADERS = {
            "X-Forwarded-For", "X-Real-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP"
    };

    private ClientIps() {
    }

    /** 解析请求来源的真实客户端 IP（代理感知） */
    public static String resolve(Context ctx) {
        String direct = normalize(ctx.ip());
        if (!isPrivateOrLoopback(direct)) {
            return direct; // 公网直连，不信任任何转发头
        }
        for (String header : FORWARDED_HEADERS) {
            String ip = firstMeaningful(ctx.header(header));
            if (ip != null) return ip;
        }
        return direct; // 无转发头时退回直连地址
    }

    /** IPv4-mapped IPv6（如 ::ffff:172.20.0.1、0:0:0:0:0:ffff:ac14:1）还原为 IPv4；
     *  双栈 JVM 直连地址可能是该形态，不归一化会被误判为公网地址而跳过转发头解析 */
    private static String normalize(String ip) {
        if (ip == null || ip.indexOf(':') < 0) return ip;
        String lower = ip.toLowerCase();
        String tail;
        if (lower.startsWith("::ffff:")) {
            tail = ip.substring(7);
        } else if (lower.startsWith("0:0:0:0:0:ffff:")) {
            tail = ip.substring(15);
        } else {
            return ip;
        }
        if (tail.indexOf('.') > 0) {                      // 点分十进制形式
            return tail;
        }
        String[] hex = tail.split(":");                   // 十六进制形式 ac14:1
        if (hex.length == 2) {
            try {
                int hi = Integer.parseInt(hex[0], 16);
                int lo = Integer.parseInt(hex[1], 16);
                if (hi <= 0xFFFF && lo <= 0xFFFF) {
                    return (hi >> 8) + "." + (hi & 0xFF) + "." + (lo >> 8) + "." + (lo & 0xFF);
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return ip;
    }

    /** 从 X-Forwarded-For 类链路中取首个合法 IP；优先公网，全内网时取首个内网段 */
    private static String firstMeaningful(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) return null;
        String firstPrivate = null;
        for (String part : headerValue.split(",")) {
            String ip = normalize(stripPort(part.trim()));
            if (!isLegalIp(ip)) continue;
            if (!isPrivateOrLoopback(ip)) return ip;
            if (firstPrivate == null) firstPrivate = ip;
        }
        return firstPrivate;
    }

    /** 去掉 IPv4 可能携带的端口；IPv6 不区分（含方括号形式亦直接放行交由校验过滤） */
    private static String stripPort(String ip) {
        int colon = ip.indexOf(':');
        if (colon > 0 && ip.lastIndexOf(':') == colon) {
            return ip.substring(0, colon);
        }
        return ip;
    }

    /** 宽松校验合法 IP（v4 点分十进制 / v6 冒号十六进制，不依赖正则） */
    private static boolean isLegalIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        if (ip.indexOf(':') >= 0) { // IPv6
            int dot = ip.indexOf('.');
            if (dot >= 0 && dot < ip.lastIndexOf(':')) return false; // 点分 v4 嵌入段只允许在末尾
            for (char c : ip.toCharArray()) {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
                        || c == ':' || c == '.')) {
                    return false;
                }
            }
            return true;
        }
        String[] segs = ip.split("\\.", -1);
        if (segs.length != 4) return false;
        for (String seg : segs) {
            if (seg.isEmpty() || seg.length() > 3) return false;
            for (char c : seg.toCharArray()) {
                if (c < '0' || c > '9') return false;
            }
            if (Integer.parseInt(seg) > 255) return false;
        }
        return true;
    }

    /** 私网/环回/链路本地地址识别（覆盖常见 v4 私网段与 v6 本地地址） */
    private static boolean isPrivateOrLoopback(String ip) {
        String lower = ip.toLowerCase();
        if (lower.indexOf(':') >= 0) { // IPv6
            if (lower.equals("::1") || lower.equals("::")) return true;
            return lower.startsWith("fc") || lower.startsWith("fd")  // ULA
                    || lower.startsWith("fe80");                     // 链路本地
        }
        String[] segs = lower.split("\\.", -1);
        if (segs.length != 4) return false;
        int a, b;
        try {
            a = Integer.parseInt(segs[0]);
            b = Integer.parseInt(segs[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        return a == 10 || a == 127 || a == 0
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 192 && b == 168)
                || (a == 169 && b == 254);
    }
}
