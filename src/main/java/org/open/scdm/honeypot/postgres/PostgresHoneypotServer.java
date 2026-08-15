package org.open.scdm.honeypot.postgres;

import org.open.scdm.honeypot.log.AttackLogger;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * PostgreSQL 蜜罐服务：模拟 PostgreSQL 17。
 * <p>
 * 不做协议交换、不读取客户端数据、不校验凭证：连接建立后立即返回 PostgreSQL 默认的
 * 认证失败响应（FATAL / SQLSTATE 28P01：
 * password authentication failed for user "postgres"），随后主动断开连接释放资源。
 */
public class PostgresHoneypotServer {
    private static final Logger LOG = Logger.getLogger(PostgresHoneypotServer.class.getName());

    /** 默认认证失败消息使用的用户名 */
    private static final String DEFAULT_USER = "postgres";

    private final int port;
    private final AttackLogger logger;
    /** 虚拟线程执行器：每个连接一条虚拟线程 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public PostgresHoneypotServer(int port, AttackLogger logger) {
        this.port = port;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("PostgreSQL 蜜罐已启动，监听端口 " + port + "（伪装版本 17）");
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

    /** 连接即发送默认认证失败 ErrorResponse，随后立即断开释放资源 */
    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "postgresql", ip, socket.getPort());
        long start = System.currentTimeMillis();
        try (socket) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            byte[] payload = errorResponse();
            out.writeByte('E');                             // ErrorResponse
            out.writeInt(4 + payload.length);               // 长度含自身 4 字节
            out.write(payload);
            out.flush();
        } catch (IOException e) {
            // 客户端提前断开：静默忽略
        } finally {
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }

    /**
     * 构造 ErrorResponse：PostgreSQL 17 认证失败的标准报文
     * S=FATAL V=FATAL C=28P01 M=password authentication failed for user "..."
     */
    private static byte[] errorResponse() {
        ByteArrayOutputStream b = new ByteArrayOutputStream(160);
        writeField(b, 'S', "FATAL");
        writeField(b, 'V', "FATAL");
        writeField(b, 'C', "28P01");
        writeField(b, 'M', "password authentication failed for user \"" + DEFAULT_USER + "\"");
        writeField(b, 'F', "auth.c");
        writeField(b, 'L', "327");
        writeField(b, 'R', "auth_failed");
        b.write(0x00); // 字段列表终止符
        return b.toByteArray();
    }

    private static void writeField(ByteArrayOutputStream b, char code, String value) {
        b.write(code);
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        b.write(bytes, 0, bytes.length);
        b.write(0x00);
    }
}
