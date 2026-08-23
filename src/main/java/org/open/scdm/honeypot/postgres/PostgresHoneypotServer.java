package org.open.scdm.honeypot.postgres;

import org.open.scdm.honeypot.log.AttackLogger;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * PostgreSQL 蜜罐服务：模拟 PostgreSQL 17。
 * <p>
 * 连接建立后解析客户端 StartupMessage 捕获用户名（遇到 SSLRequest 先回 'N' 拒绝 TLS，
 * 继续读取明文启动报文），随后下发 AuthenticationCleartextPassword 索取口令，
 * 捕获客户端提交的明文密码并通过 AttackLogger 记录 auth_attempt 事件。
 * 无论提交什么凭证，一律返回认证失败响应（FATAL / SQLSTATE 28P01：
 * password authentication failed for user "用户"），错误提示中的用户名取自客户端实际提交的账号，
 * 随后主动断开连接释放资源。
 * <p>
 * 并发保护：活跃连接数限制为 {@link #MAX_CONNECTIONS}，超限连接直接按 PostgreSQL 标准
 * 返回连接数超限错误（FATAL / SQLSTATE 53300：sorry, too many clients already）后断开，
 * 防止恶意客户端无限建连耗尽服务器资源。
 */
public class PostgresHoneypotServer {
    private static final Logger LOG = Logger.getLogger(PostgresHoneypotServer.class.getName());

    /** 协议版本 3.0 标识（StartupMessage 版本字段） */
    private static final int PROTOCOL_V3 = 196608;
    /** SSLRequest 请求码：客户端请求 TLS 升级 */
    private static final int SSL_REQUEST = 80877103;
    /** 认证失败 SQLSTATE */
    private static final String SQLSTATE_AUTH_FAILED = "28P01";
    /** 连接数超限 SQLSTATE */
    private static final String SQLSTATE_TOO_MANY_CLIENTS = "53300";

    /** 等待客户端报文的最长时间（毫秒），防止扫描器挂住连接 */
    private static final int READ_TIMEOUT_MS = 15_000;
    /** 最大并发连接数：超限连接直接返回超限错误后断开，防止无限连接耗尽资源 */
    private static final int MAX_CONNECTIONS = 20;
    /** 可接受的最大报文长度（防止超大报文耗尽内存） */
    private static final int MAX_MESSAGE_LENGTH = 0x10000;

    private final int port;
    private final AttackLogger logger;
    /** 虚拟线程执行器：每个连接一条虚拟线程 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    /** 当前活跃连接数：原子计数，超过 {@link #MAX_CONNECTIONS} 的新连接立即拒绝 */
    private final AtomicInteger activeConnections = new AtomicInteger();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public PostgresHoneypotServer(int port, AttackLogger logger) {
        this.port = port;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("PostgreSQL 蜜罐已启动，监听端口 " + port + "（伪装版本 17，最大并发连接 " + MAX_CONNECTIONS + "）");
        pool.submit(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    pool.submit(() -> handleClient(client));
                } catch (IOException e) {
                    if (running) LOG.warning("PostgreSQL accept 失败: " + e.getMessage());
                }
            }
        });
    }

    public void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        pool.shutdownNow();
    }

    /** 协议交互捕获客户端登录凭证，无论凭证是什么一律返回认证失败后断开 */
    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "postgresql", ip, socket.getPort());
        long start = System.currentTimeMillis();
        // 并发连接限流：先原子递增再判断，超限立即回退计数并按 PostgreSQL 标准返回超限错误后断开，
        // 避免恶意客户端无限建连耗尽服务器资源（先递增后判断保证并发下不超限）
        if (activeConnections.incrementAndGet() > MAX_CONNECTIONS) {
            activeConnections.decrementAndGet();
            try (socket) {
                sendError(socket, SQLSTATE_TOO_MANY_CLIENTS,
                        "sorry, too many clients already", "proc.c", "BackendStartup");
            } catch (IOException e) {
                // 客户端提前断开：静默忽略
            } finally {
                logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
            }
            return;
        }
        try (socket) {
            socket.setSoTimeout(READ_TIMEOUT_MS);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            String user = readStartup(in, out);
            if (user == null) return;               // 非标准流量（取消请求/旧协议/缺用户名）：静默断开
            // 索取明文口令：诱导客户端提交密码
            out.writeByte('R');
            out.writeInt(8);
            out.writeInt(3);                        // AuthenticationCleartextPassword
            out.flush();
            String password = readPassword(in);
            logger.authAttempt(sessionId, "postgresql", ip, user,
                    password.isEmpty() ? "(空)" : password, false);
            sendError(socket, SQLSTATE_AUTH_FAILED,
                    "password authentication failed for user \"" + user + "\"", "auth.c", "auth_failed");
        } catch (SocketTimeoutException | EOFException e) {
            // 扫描器未发送完整报文或客户端提前断开：静默忽略
        } catch (IOException e) {
            // I/O 异常：静默忽略
        } finally {
            activeConnections.decrementAndGet();
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }

    /**
     * 读取启动阶段报文并返回 StartupMessage 中的用户名。
     * 遇到 SSLRequest 先回 'N' 拒绝 TLS 后继续读取明文启动报文；
     * CancelRequest 等非启动报文、非 3.0 协议或缺少 user 字段时返回 null（直接断开）。
     */
    private static String readStartup(DataInputStream in, DataOutputStream out) throws IOException {
        byte[] msg = readMessage(in);
        if (msg.length == 4) {
            int code = readInt(msg, 0);
            if (code == SSL_REQUEST) {
                out.writeByte('N');                 // 不支持 SSL：客户端将以明文重新发送启动报文
                out.flush();
                msg = readMessage(in);
            } else {
                return null;                        // CancelRequest/GSSENCRequest：静默断开
            }
        }
        if (msg.length < 8 || readInt(msg, 0) != PROTOCOL_V3) return null;
        // 参数区为 key\0value\0 键值对序列，以单个 \0 结束
        int pos = 4;
        while (true) {
            int keyEnd = indexOf(msg, (byte) 0x00, pos);
            if (keyEnd < 0) break;
            String key = new String(msg, pos, keyEnd - pos, StandardCharsets.UTF_8);
            pos = keyEnd + 1;
            int valEnd = indexOf(msg, (byte) 0x00, pos);
            if (valEnd < 0) break;
            String value = new String(msg, pos, valEnd - pos, StandardCharsets.UTF_8);
            pos = valEnd + 1;
            if ("user".equals(key)) return value;
        }
        return null;
    }

    /** 读取 PasswordMessage 并返回客户端提交的口令（剥离 NUL 终止符） */
    private static String readPassword(DataInputStream in) throws IOException {
        int type = in.readUnsignedByte();
        byte[] body = readMessage(in);
        if (type != 'p') return "";
        int end = indexOf(body, (byte) 0x00, 0);
        int len = (end < 0) ? body.length : end;
        return new String(body, 0, len, StandardCharsets.UTF_8);
    }

    /** 读取启动阶段消息（无类型字节，4 字节长度含自身）；长度非法时抛出 I/O 异常 */
    private static byte[] readMessage(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 4 || len > MAX_MESSAGE_LENGTH) throw new IOException("非法报文长度: " + len);
        byte[] body = new byte[len - 4];
        in.readFully(body);
        return body;
    }

    /** 发送 ErrorResponse（FATAL 级别） */
    private static void sendError(Socket socket, String sqlstate, String message,
                                  String file, String routine) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(160);
        writeField(b, 'S', "FATAL");
        writeField(b, 'V', "FATAL");
        writeField(b, 'C', sqlstate);
        writeField(b, 'M', message);
        writeField(b, 'F', file);
        writeField(b, 'L', "327");
        writeField(b, 'R', routine);
        b.write(0x00);                              // 字段列表终止符
        byte[] payload = b.toByteArray();
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeByte('E');                         // ErrorResponse
        out.writeInt(4 + payload.length);           // 长度含自身 4 字节
        out.write(payload);
        out.flush();
    }

    private static void writeField(ByteArrayOutputStream b, char code, String value) {
        b.write(code);
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        b.write(bytes, 0, bytes.length);
        b.write(0x00);
    }

    private static int readInt(byte[] data, int off) {
        return ((data[off] & 0xFF) << 24) | ((data[off + 1] & 0xFF) << 16)
                | ((data[off + 2] & 0xFF) << 8) | (data[off + 3] & 0xFF);
    }

    private static int indexOf(byte[] data, byte target, int from) {
        for (int i = from; i < data.length; i++) {
            if (data[i] == target) return i;
        }
        return -1;
    }
}
