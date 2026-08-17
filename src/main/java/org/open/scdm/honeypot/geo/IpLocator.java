package org.open.scdm.honeypot.geo;

import org.lionsoul.ip2region.service.Config;
import org.lionsoul.ip2region.service.Ip2Region;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * IP 归属地定位器：基于 ip2region 3.x 的 xdb 外部库文件离线解析 IPv4/IPv6 归属地，
 * 供攻击日志（sessions）与 Web 审计日志（sys_audit_log）记录“国家 省份 城市”。
 * <p>
 * v4 / v6 两个库文件独立可选：哪个存在加载哪个，仅单边可用时另一边查询返回 null；
 * 均采用 BufferCache 策略将库文件整体加载进内存（v4 约 11MB），查询为纯内存检索，
 * 无锁竞争、无磁盘 I/O，结果另加进程内缓存，同一 IP 仅首次查询命中 xdb。
 * <p>
 * 容错设计：库文件全部缺失或损坏时降级为空实现（locate 恒返回 null），
 * 不影响蜜罐与 Web 控制台的正常启动运行。
 */
public class IpLocator implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(IpLocator.class.getName());

    /** 缓存容量上限：蜜罐场景来源 IP 数量有限，超限后仅查询不缓存，防止异常流量撑爆内存 */
    private static final int CACHE_LIMIT = 65536;

    /** ip2region v4+v6 统一查询服务；两个库文件均不可用时为 null（降级为空实现） */
    private final Ip2Region searcher;

    /** IP -> 归属地结果缓存；未命中库的 IP 缓存空串哨兵，避免重复检索 */
    private final Map<String, String> cache = new ConcurrentHashMap<>();

    private IpLocator(Ip2Region searcher) {
        this.searcher = searcher;
    }

    /**
     * 加载 v4 / v6 xdb 库文件并构造定位器；文件缺失或加载失败时对应库跳过，
     * 两者均不可用时返回降级实例并告警，不抛异常。
     */
    public static IpLocator load(Path v4File, Path v6File) {
        Config v4Config = buildConfig(v4File, true);
        Config v6Config = buildConfig(v6File, false);
        if (v4Config == null && v6Config == null) {
            LOG.warning("未加载到任何 IP 库文件（log.ipdb_v4 / log.ipdb_v6），归属地留空");
            return new IpLocator(null);
        }
        try {
            Ip2Region searcher = Ip2Region.create(v4Config, v6Config);
            LOG.info("IP 归属地库已加载: v4=" + (v4Config != null) + ", v6=" + (v6Config != null));
            return new IpLocator(searcher);
        } catch (Exception e) {
            LOG.warning("IP 归属地服务初始化失败，归属地留空: " + e.getMessage());
            return new IpLocator(null);
        }
    }

    /** 构造单侧库配置；文件缺失或加载失败时返回 null（该侧跳过） */
    private static Config buildConfig(Path xdbFile, boolean v4) {
        String tag = v4 ? "v4" : "v6";
        if (xdbFile == null || xdbFile.toString().isBlank()) {
            LOG.info("未配置 " + tag + " IP 库文件，" + tag + " 归属地留空");
            return null;
        }
        if (Files.notExists(xdbFile)) {
            LOG.warning(tag + " IP 库文件不存在: " + xdbFile.toAbsolutePath()
                    + "（放置 ip2region " + tag + " xdb 后即可解析对应归属地）");
            return null;
        }
        try {
            var builder = Config.custom()
                    // BufferCache：库文件整体进内存，纯内存检索，蜜罐低流量场景最优
                    .setCachePolicy(Config.BufferCache)
                    .setXdbFile(xdbFile.toFile());
            Config config = v4 ? builder.asV4() : builder.asV6();
            LOG.info(tag + " IP 归属地库已加载: " + xdbFile.toAbsolutePath());
            return config;
        } catch (Exception e) {
            LOG.warning(tag + " IP 库文件加载失败，" + tag + " 归属地留空: " + e.getMessage());
            return null;
        }
    }

    /** xdb 库是否可用（v4 / v6 任意一个已加载） */
    public boolean isAvailable() {
        return searcher != null;
    }

    /**
     * 解析 IP（IPv4 / IPv6 均支持）归属地为“国家 省份 城市”（空格分隔，过滤未知占位与相邻重复段）。
     *
     * @return 归属地字符串；库不可用/非法地址/库中无记录时返回 null；内网 IP 返回“内网IP”
     */
    public String locate(String ip) {
        if (searcher == null || ip == null || ip.isBlank()) return null;
        String key = ip.trim();
        if (isPrivate(key)) return "内网IP";
        String cached = cache.get(key);
        if (cached != null) return cached.isEmpty() ? null : cached;
        String location = search(key);
        if (cache.size() < CACHE_LIMIT) {
            cache.put(key, location == null ? "" : location);
        }
        return location;
    }

    /** xdb 检索：对应协议库未加载时 Ip2Region 返回 null；非法地址抛异常按无记录处理 */
    private String search(String ip) {
        try {
            return format(searcher.search(ip));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            return null; // 非法地址或检索失败，按无记录处理
        }
    }

    /** 将“国家|区域|省份|城市|ISP”整理为“国家 省份 城市”：跳过 0 占位符并合并相邻重复段（如“上海 上海”） */
    static String format(String region) {
        if (region == null || region.isBlank()) return null;
        String[] parts = region.split("\\|", -1);
        StringBuilder sb = new StringBuilder();
        String last = null;
        for (int idx : new int[]{0, 2, 3}) { // 国家、省份、城市（区域字段不用）
            if (idx >= parts.length) break;
            String v = parts[idx].trim();
            if (v.isEmpty() || "0".equals(v) || v.equals(last)) continue;
            if (!sb.isEmpty()) sb.append(' ');
            sb.append(v);
            last = v;
        }
        return sb.isEmpty() ? null : sb.toString();
    }

    /** 内网/环回/链路本地地址识别（IPv4 + IPv6）：命中直接返回“内网IP”，避免无意义的库检索 */
    static boolean isPrivate(String ip) {
        String lower = ip.toLowerCase();
        // IPv6：环回（含 Jetty 展开写法）、ULA fc00::/7、链路本地 fe80::/10
        if ("::1".equals(lower) || "0:0:0:0:0:0:0:1".equals(lower) || "::".equals(lower)) return true;
        if (lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80")) return true;
        // IPv4 私有段
        String[] seg = ip.split("\\.");
        if (seg.length != 4) return false; // 其余 IPv6 公网地址交由 v6 库检索
        try {
            int a = Integer.parseInt(seg[0]);
            int b = Integer.parseInt(seg[1]);
            if (a > 255 || b > 255) return false;
            return a == 10                                          // 10.0.0.0/8
                    || (a == 172 && b >= 16 && b <= 31)             // 172.16.0.0/12
                    || (a == 192 && b == 168)                       // 192.168.0.0/16
                    || a == 127 || a == 0                           // 环回 / 本网络
                    || (a == 169 && b == 254);                      // 链路本地
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    public void close() {
        if (searcher != null) {
            try {
                searcher.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception ignored) {
            }
        }
    }
}
