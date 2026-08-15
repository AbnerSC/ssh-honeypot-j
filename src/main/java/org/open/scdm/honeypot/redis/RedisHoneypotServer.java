package org.open.scdm.honeypot.redis;

import org.open.scdm.honeypot.log.AttackLogger;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Redis 蜜罐服务：模拟 Redis 7。
 * <p>
 * 不读取任何命令、不校验凭证：连接建立后立即返回 Redis 默认的认证失败响应
 * （-WRONGPASS invalid username-password pair or user is disabled.），
 * 随后主动断开连接释放资源。
 */
public class RedisHoneypotServer {
    private static final Logger LOG = Logger.getLogger(RedisHoneypotServer.class.getName());

    /** Redis 6+ ACL 风格的默认认证失败响应（7.x 同样使用） */
    private static final byte[] RESP_WRONGPASS =
            "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
                    .getBytes(StandardCharsets.US_ASCII);

    private final int port;
    private final AttackLogger logger;
    /** 虚拟线程执行器：每个连接一条虚拟线程 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public RedisHoneypotServer(int port, AttackLogger logger) {
        this.port = port;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("Redis 蜜罐已启动，监听端口 " + port + "（伪装版本 7）");
        pool.submit(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    pool.submit(() -> handleClient(client));
                } catch (IOException e) {
                    if (running) LOG.warning("Redis accept 失败: " + e.getMessage());
                }
            }
        });
    }

    public void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        pool.shutdownNow();
    }

    /** 连接即发送默认认证失败响应，随后立即断开释放资源 */
    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "redis", ip, socket.getPort());
        long start = System.currentTimeMillis();
        try (socket) {
            socket.getOutputStream().write(RESP_WRONGPASS);
            socket.getOutputStream().flush();
        } catch (IOException e) {
            // 客户端提前断开：静默忽略
        } finally {
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }
}
