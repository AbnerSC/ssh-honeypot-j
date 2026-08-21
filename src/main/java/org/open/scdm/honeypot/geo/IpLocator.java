package org.open.scdm.honeypot.geo;

import org.lionsoul.ip2region.service.Config;
import org.lionsoul.ip2region.service.Ip2Region;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * IP 归属地定位器：基于 ip2region 3.x 的 xdb 库文件离线解析 IPv4/IPv6 归属地，
 * 供攻击日志（sessions）与 Web 审计日志（sys_audit_log）记录“国家 省份 城市”。
 * <p>
 * 库文件加载优先级：配置的外部文件路径 > jar 内置资源（db/ip2region_v4.xdb、db/ip2region_v6.xdb，
 * 随 fat-jar 打包，部署无需额外携带）；v4 / v6 两个库独立可选，仅单边可用时另一边查询返回 null；
 * 均采用 VIndexCache 策略：仅向量索引（约 512KB/库）常驻内存，数据段按需从文件读取，
 * 避免 37MB 级 v6 库整体进内存在低配额容器（Docker 默认堆约容器内存 1/4）中 OOM；
 * 查询另有进程内结果缓存，同一 IP 仅首次查询触发文件检索。
 * <p>
 * 容错设计：库文件全部缺失或损坏时降级为空实现（locate 恒返回 null），
 * 不影响蜜罐与 Web 控制台的正常启动运行。
 */
public class IpLocator implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(IpLocator.class.getName());

    /** 缓存容量上限：蜜罐场景来源 IP 数量有限，超限后仅查询不缓存，防止异常流量撑爆内存 */
    private static final int CACHE_LIMIT = 8192;

    /** jar 内置 xdb 库资源路径：随 fat-jar 打包，外部文件缺失时兜底加载 */
    private static final String BUILTIN_V4 = "db/ip2region_v4.xdb";
    private static final String BUILTIN_V6 = "db/ip2region_v6.xdb";

    /** ip2region v4+v6 统一查询服务；两个库文件均不可用时为 null（降级为空实现） */
    private final Ip2Region searcher;

    /** IP -> 归属地结果缓存；未命中库的 IP 缓存空串哨兵，避免重复检索 */
    private final Map<String, String> cache = new ConcurrentHashMap<>();

    private IpLocator(Ip2Region searcher) {
        this.searcher = searcher;
    }

    /**
     * 加载 v4 / v6 xdb 库文件并构造定位器；外部文件缺失时回退加载 jar 内置资源，
     * 两者均不可用时返回降级实例并告警，不抛异常。
     */
    public static IpLocator load(Path v4File, Path v6File) {
        Config v4Config = buildConfig(v4File, BUILTIN_V4, true);
        Config v6Config = buildConfig(v6File, BUILTIN_V6, false);
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

    /** 构造单侧库配置：优先外部文件，缺失时回退 jar 内置资源，均不可用时返回 null（该侧跳过） */
    private static Config buildConfig(Path xdbFile, String builtinResource, boolean v4) {
        String tag = v4 ? "v4" : "v6";
        boolean external = xdbFile != null && !xdbFile.toString().isBlank() && Files.exists(xdbFile);
        if (xdbFile != null && !xdbFile.toString().isBlank() && !external) {
            LOG.info(tag + " IP 库文件不存在: " + xdbFile.toAbsolutePath() + "，回退使用 jar 内置库");
        }
        try {
            // VIndexCache：仅向量索引（约 512KB/库）进内存，数据段按需读取；
            // 避免 BufferCache 整体加载 37MB 级 v6 库导致低配额容器（Docker 默认堆约容器内存 1/4）OOM。
            // 蜜罐低流量 + 下方进程内结果缓存，单次文件检索开销可忽略。
            // 注意：ip2region 仅 BufferCache 支持 InputStream，故内置库需先释放为临时文件。
            var builder = Config.custom().setCachePolicy(Config.VIndexCache);
            String source;
            if (external) {
                builder.setXdbFile(xdbFile.toFile());
                source = xdbFile.toAbsolutePath().toString();
            } else {
                Path tmp = extractBuiltin(builtinResource, tag);
                if (tmp == null) {
                    LOG.warning(tag + " IP 库既无外部文件也无 jar 内置资源 " + builtinResource
                            + "，" + tag + " 归属地留空");
                    return null;
                }
                builder.setXdbFile(tmp.toFile());
                source = "classpath:" + builtinResource + "（已释放到 " + tmp + "）";
            }
            Config config = v4 ? builder.asV4() : builder.asV6();
            LOG.info(tag + " IP 归属地库已加载: " + source);
            return config;
        } catch (Exception e) {
            LOG.warning(tag + " IP 库文件加载失败，" + tag + " 归属地留空: " + e.getMessage());
            return null;
        }
    }

    /**
     * 将 jar 内置 xdb 库释放到临时文件（ip2region 仅 BufferCache 支持流式加载，
     * VIndexCache 需要可随机读取的文件）；读取为瞬时占用，写入后字节数组即可回收。
     *
     * @return 临时文件路径（进程退出时自动删除）；内置资源不存在或释放失败时返回 null
     */
    private static Path extractBuiltin(String builtinResource, String tag) {
        byte[] content;
        try (InputStream in = IpLocator.class.getResourceAsStream("/" + builtinResource)) {
            if (in == null) return null;
            content = in.readAllBytes();
        } catch (IOException e) {
            LOG.warning(tag + " IP 内置库读取失败 " + builtinResource + ": " + e.getMessage());
            return null;
        }
        try {
            Path tmp = Files.createTempFile("ip2region-" + tag + "-", ".xdb");
            tmp.toFile().deleteOnExit();
            Files.write(tmp, content);
            return tmp;
        } catch (IOException e) {
            LOG.warning(tag + " IP 内置库释放临时文件失败: " + e.getMessage());
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
