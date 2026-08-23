package org.open.scdm.honeypot.mysql;

import org.open.scdm.honeypot.log.AttackLogger;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * MySQL 蜜罐服务：模拟 MySQL 8.4。
 * <p>
 * 连接建立后先下发 HandshakeV10 握手包诱导客户端提交登录凭证，解析
 * HandshakeResponse 捕获攻击者输入的用户名与认证数据（认证数据记录为十六进制摘要，
 * MySQL 协议传输的是密码加盐散列而非明文），并通过 AttackLogger 记录 auth_attempt 事件。
 * 无论提交什么凭证，一律返回认证失败错误（ERROR 1045 / SQLSTATE 28000：
 * Access denied for user '用户'@'ip'），错误提示中的用户名取自客户端实际提交的账号，
 * 随后主动断开连接释放资源。
 * <p>
 * 并发保护：活跃连接数限制为 {@link #MAX_CONNECTIONS}，超限时不下发握手包，
 * 直接按 MySQL 标准返回 ERROR 1040 / SQLSTATE 08004（Too many connections）后断开，
 * 防止恶意客户端无限建连耗尽服务器资源。
 */
public class MySqlHoneypotServer {
    private static final Logger LOG = Logger.getLogger(MySqlHoneypotServer.class.getName());

    private static final int ER_ACCESS_DENIED = 1045;
    private static final String SQLSTATE_ACCESS_DENIED = "28000";
    /** 连接数超限错误：MySQL 服务端达到最大连接数时的标准响应 */
    private static final int ER_TOO_MANY_CONNECTIONS = 1040;
    private static final String SQLSTATE_TOO_MANY_CONNECTIONS = "08004";

    /** 能力标志：4.1+ 协议（客户端未携带该标志时视为非协议流量，直接断开） */
    private static final int CLIENT_PROTOCOL_41 = 0x00000200;
    /** 能力标志：4.1+ 认证（1 字节长度前缀的认证数据） */
    private static final int CLIENT_SECURE_CONNECTION = 0x00008000;
    /** 能力标志：认证数据采用 length-encoded 长度前缀 */
    private static final int CLIENT_PLUGIN_AUTH_LENENC = 0x00200000;

    /** 等待客户端登录报文的最长时间（毫秒），防止扫描器挂住连接 */
    private static final int READ_TIMEOUT_MS = 15_000;
    /** 最大并发连接数：超限连接直接返回 1040 后断开，防止无限连接耗尽资源 */
    private static final int MAX_CONNECTIONS = 20;
    /** 伪造服务器版本号（握手包中展示） */
    private static final String SERVER_VERSION = "8.4.0";
    /** 认证插件：兼容性最好，绝大多数客户端/扫描器均支持 */
    private static final String AUTH_PLUGIN = "mysql_native_password";
    /** 固定认证盐（20 字节）：客户端凭证不做校验，无需随机生成 */
    private static final byte[] SALT = {
            0x6a, 0x31, 0x5e, 0x24, 0x77, 0x2b, 0x69, 0x33,
            0x4d, 0x1f, 0x08, 0x6c, 0x55, 0x41, 0x70, 0x2e,
            0x36, 0x0d, 0x59, 0x18};

    private final int port;
    private final AttackLogger logger;
    /** 虚拟线程执行器：每个连接一条虚拟线程 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    /** 当前活跃连接数：原子计数，超过 {@link #MAX_CONNECTIONS} 的新连接立即拒绝 */
    private final AtomicInteger activeConnections = new AtomicInteger();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public MySqlHoneypotServer(int port, AttackLogger logger) {
        this.port = port;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("MySQL 蜜罐已启动，监听端口 " + port + "（伪装版本 8.4，最大并发连接 " + MAX_CONNECTIONS + "）");
        pool.submit(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    pool.submit(() -> handleClient(client));
                } catch (IOException e) {
                    if (running) LOG.warning("MySQL accept 失败: " + e.getMessage());
                }
            }
        });
    }

    public void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        pool.shutdownNow();
    }

    /** 下发握手包捕获客户端登录凭证，无论凭证是什么一律返回认证失败后断开 */
    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "mysql", ip, socket.getPort());
        long start = System.currentTimeMillis();
        String user = "unknown";
        boolean usingPassword = false;
        // 并发连接限流：先原子递增再判断，超限立即回退计数并按 MySQL 标准返回 1040 后断开，
        // 避免恶意客户端无限建连耗尽服务器资源（先递增后判断保证并发下不超限）
        if (activeConnections.incrementAndGet() > MAX_CONNECTIONS) {
            activeConnections.decrementAndGet();
            try (socket) {
                sendPacket(socket.getOutputStream(), 0, tooManyConnections());
            } catch (IOException e) {
                // 客户端提前断开：静默忽略
            } finally {
                logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
            }
            return;
        }
        try (socket) {
            socket.setSoTimeout(READ_TIMEOUT_MS);
            sendPacket(socket.getOutputStream(), 0, handshake());
            byte[] resp = readPacket(socket);
            String[] cred = parseHandshakeResponse(resp);
            if (cred != null) {
                user = cred[0];
                usingPassword = !cred[1].isEmpty();
                // MySQL 协议传输的是密码散列，记录十六进制认证数据；空认证数据表示未输入密码
                logger.authAttempt(sessionId, "mysql", ip, user,
                        usingPassword ? cred[1] : "(空)", false);
            }
            sendPacket(socket.getOutputStream(), 2, accessDenied(user, ip, usingPassword));
        } catch (SocketTimeoutException | EOFException e) {
            // 扫描器未发送登录报文或客户端提前断开：静默忽略，不发错误包（协议报文都算不上）
        } catch (IOException e) {
            // I/O 异常：静默忽略
        } finally {
            activeConnections.decrementAndGet();
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }

    /** 构造 ERR 包：ERROR 1040 (08004) Too many connections（MySQL 服务端达到最大连接数时的标准响应） */
    private static byte[] tooManyConnections() {
        byte[] msg = "Too many connections".getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream b = new ByteArrayOutputStream(16 + msg.length);
        b.write(0xFF);                                          // ERR 包头
        b.write(ER_TOO_MANY_CONNECTIONS & 0xFF);                // 错误码小端
        b.write((ER_TOO_MANY_CONNECTIONS >> 8) & 0xFF);
        b.write('#');                                           // SQLSTATE 标记
        writeBytes(b, SQLSTATE_TOO_MANY_CONNECTIONS.getBytes(StandardCharsets.US_ASCII));
        writeBytes(b, msg);
        return b.toByteArray();
    }

    /**
     * 构造 HandshakeV10 握手包：协议版本 10 + 服务器版本 + 认证盐 + 能力标志。
     * 不声明 CLIENT_SSL，避免诱导客户端发起 TLS 升级。
     */
    private static byte[] handshake() {
        int caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | 0x00080000 /* CLIENT_PLUGIN_AUTH */;
        ByteArrayOutputStream b = new ByteArrayOutputStream(128);
        b.write(0x0A);                                              // 协议版本 10（HandshakeV10）
        writeBytes(b, SERVER_VERSION.getBytes(StandardCharsets.US_ASCII));
        b.write(0x00);                                              // 版本号 NUL 终止
        writeBytes(b, new byte[]{0x00, 0x00, 0x01, 0x2A});          // 线程 ID（伪造）
        writeBytes(b, SALT, 0, 8);                                  // auth-plugin-data 第 1 部分（8 字节）
        b.write(0x00);                                              // 填充字节
        b.write(caps & 0xFF);                                       // 能力标志低 16 位（小端）
        b.write((caps >> 8) & 0xFF);
        b.write(0x2D);                                              // 字符集 utf8mb4_0900_ai_ci
        writeBytes(b, new byte[]{0x02, 0x00});                      // 状态标志 SERVER_STATUS_AUTOCOMMIT
        b.write((caps >> 16) & 0xFF);                               // 能力标志高 16 位（小端）
        b.write((caps >> 24) & 0xFF);
        b.write(SALT.length + 1);                                   // auth-plugin-data 总长度（含终止符）
        writeBytes(b, new byte[10]);                                // 保留字节（全 0）
        writeBytes(b, SALT, 8, SALT.length - 8);                    // auth-plugin-data 第 2 部分（12 字节）
        b.write(0x00);                                              // 第 2 部分 NUL 终止（凑满 13 字节）
        writeBytes(b, AUTH_PLUGIN.getBytes(StandardCharsets.US_ASCII));
        b.write(0x00);                                              // 插件名 NUL 终止
        return b.toByteArray();
    }

    /** 读取一个完整 MySQL 包并返回负载；报文不合法（超大长度）时返回空数组 */
    private static byte[] readPacket(Socket socket) throws IOException {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        int len = in.readUnsignedByte() | (in.readUnsignedByte() << 8) | (in.readUnsignedByte() << 16);
        in.readUnsignedByte(); // 序号（不校验）
        if (len <= 0 || len > 0x10000) return new byte[0];
        byte[] payload = new byte[len];
        in.readFully(payload);
        return payload;
    }

    /**
     * 解析 HandshakeResponse41：提取用户名与认证数据。
     * 返回 {用户名, 认证数据十六进制}；报文过短或非 4.1+ 协议时返回 null。
     */
    private static String[] parseHandshakeResponse(byte[] p) {
        if (p.length < 32) return null;                             // 头部固定 32 字节（4+4+1+23）
        int caps = (p[0] & 0xFF) | ((p[1] & 0xFF) << 8) | ((p[2] & 0xFF) << 16) | ((p[3] & 0xFF) << 24);
        if ((caps & CLIENT_PROTOCOL_41) == 0) return null;          // 旧协议流量不解析，直接断开
        int pos = 32;                                               // 跳过能力(4)+最大包长(4)+字符集(1)+保留(23)
        int nul = indexOf(p, (byte) 0x00, pos);
        if (nul < 0) return null;
        String user = new String(p, pos, Math.min(nul - pos, 512), StandardCharsets.UTF_8);
        pos = nul + 1;
        int authLen;
        if ((caps & CLIENT_PLUGIN_AUTH_LENENC) != 0) {              // length-encoded 长度前缀（仅支持单字节）
            if (pos >= p.length) return null;
            authLen = p[pos++] & 0xFF;
        } else if ((caps & CLIENT_SECURE_CONNECTION) != 0) {        // 4.1+ 认证：1 字节长度前缀
            if (pos >= p.length) return null;
            authLen = p[pos++] & 0xFF;
        } else {                                                    // 兼容 3.23 风格：NUL 终止
            int end = indexOf(p, (byte) 0x00, pos);
            authLen = (end < 0) ? (p.length - pos) : (end - pos);
        }
        authLen = Math.min(authLen, p.length - pos);
        byte[] auth = new byte[Math.max(authLen, 0)];
        System.arraycopy(p, pos, auth, 0, auth.length);
        return new String[]{user, HexFormat.of().formatHex(auth)};
    }

    private static int indexOf(byte[] data, byte target, int from) {
        for (int i = from; i < data.length; i++) {
            if (data[i] == target) return i;
        }
        return -1;
    }

    /** 构造 ERR 包：ERROR 1045 (28000) Access denied，用户名取自客户端实际提交的账号 */
    private static byte[] accessDenied(String user, String ip, boolean usingPassword) {
        String msg = String.format("Access denied for user '%s'@'%s' (using password: %s)",
                user, ip, usingPassword ? "YES" : "NO");
        ByteArrayOutputStream b = new ByteArrayOutputStream(48 + msg.length());
        b.write(0xFF);                                      // ERR 包头
        b.write(ER_ACCESS_DENIED & 0xFF);                   // 错误码小端
        b.write((ER_ACCESS_DENIED >> 8) & 0xFF);
        b.write('#');                                       // SQLSTATE 标记
        writeBytes(b, SQLSTATE_ACCESS_DENIED.getBytes(StandardCharsets.US_ASCII));
        writeBytes(b, msg.getBytes(StandardCharsets.UTF_8));
        return b.toByteArray();
    }

    /** 发送一个 MySQL 包（3 字节长度 + 1 字节序号） */
    private static void sendPacket(OutputStream out, int seq, byte[] payload) throws IOException {
        out.write(new byte[]{
                (byte) (payload.length & 0xFF),
                (byte) ((payload.length >> 8) & 0xFF),
                (byte) ((payload.length >> 16) & 0xFF),
                (byte) seq});
        out.write(payload);
        out.flush();
    }

    private static void writeBytes(ByteArrayOutputStream b, byte[] bytes) {
        b.write(bytes, 0, bytes.length);
    }

    private static void writeBytes(ByteArrayOutputStream b, byte[] bytes, int off, int len) {
        b.write(bytes, off, len);
    }
}
