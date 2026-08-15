package org.open.scdm.honeypot.mysql;

import org.open.scdm.honeypot.log.AttackLogger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * MySQL 蜜罐服务：模拟 MySQL 8.4。
 * <p>
 * 不做握手协商、不读取客户端数据、不校验凭证：连接建立后立即返回 MySQL 默认的
 * 认证失败错误（ERROR 1045 / SQLSTATE 28000：
 * Access denied for user 'root'@'ip' (using password: NO)），随后主动断开连接释放资源。
 */
public class MySqlHoneypotServer {
    private static final Logger LOG = Logger.getLogger(MySqlHoneypotServer.class.getName());

    private static final int ER_ACCESS_DENIED = 1045;
    private static final String SQLSTATE_ACCESS_DENIED = "28000";

    private final int port;
    private final AttackLogger logger;
    /** 虚拟线程执行器：每个连接一条虚拟线程 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public MySqlHoneypotServer(int port, AttackLogger logger) {
        this.port = port;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("MySQL 蜜罐已启动，监听端口 " + port + "（伪装版本 8.4）");
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

    /** 连接即发送默认认证失败 ERR 包，随后立即断开释放资源 */
    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "mysql", ip, socket.getPort());
        long start = System.currentTimeMillis();
        try (socket) {
            sendPacket(socket.getOutputStream(), 0, accessDenied(ip));
        } catch (IOException e) {
            // 客户端提前断开：静默忽略
        } finally {
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }

    /** 构造 ERR 包：ERROR 1045 (28000) Access denied */
    private static byte[] accessDenied(String ip) {
        String msg = String.format("Access denied for user 'root'@'%s' (using password: NO)", ip);
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
}
