package org.open.scdm.honeypot.redis;

import org.open.scdm.honeypot.log.AttackLogger;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * Redis 蜜罐服务：模拟 Redis 7。
 * <p>
 * 连接建立后读取客户端命令（兼容 RESP 数组与内联命令两种形式）：
 * 对非认证命令按真实 Redis 返回 -NOAUTH 要求认证，诱导客户端提交 AUTH；
 * 收到 AUTH（或携带 AUTH 参数的 HELLO）时捕获账号与密码，
 * 并通过 AttackLogger 记录 auth_attempt 事件，随后无论提交什么凭证，
 * 一律返回认证失败响应（-WRONGPASS invalid username-password pair or user is disabled.）
 * 并主动断开连接释放资源。
 * <p>
 * 并发保护：活跃连接数限制为 {@link #MAX_CONNECTIONS}，超限连接直接按 Redis 标准
 * 返回连接数超限错误（-ERR max number of clients reached）后断开，
 * 防止恶意客户端无限建连耗尽服务器资源。
 */
public class RedisHoneypotServer {
    private static final Logger LOG = Logger.getLogger(RedisHoneypotServer.class.getName());

    /** Redis 6+ ACL 风格的认证失败响应（7.x 同样使用） */
    private static final byte[] RESP_WRONGPASS =
            "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
                    .getBytes(StandardCharsets.US_ASCII);
    /** 要求认证响应：未认证时执行其他命令的标准回复，用于诱导客户端提交 AUTH */
    private static final byte[] RESP_NOAUTH =
            "-NOAUTH Authentication required.\r\n".getBytes(StandardCharsets.US_ASCII);
    /** 连接数超限响应：Redis 服务端达到 maxclients 时的标准回复 */
    private static final byte[] RESP_TOO_MANY =
            "-ERR max number of clients reached\r\n".getBytes(StandardCharsets.US_ASCII);
    /** AUTH 参数个数错误响应 */
    private static final byte[] RESP_AUTH_ARGS =
            "-ERR wrong number of arguments for 'auth' command\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] RESP_OK = "+OK\r\n".getBytes(StandardCharsets.US_ASCII);

    /** Redis 6+ 单参数 AUTH（仅密码）视为默认用户认证 */
    private static final String DEFAULT_USER = "default";

    /** 等待客户端命令的最长时间（毫秒），防止扫描器挂住连接 */
    private static final int READ_TIMEOUT_MS = 15_000;
    /** 最大并发连接数：超限连接直接返回超限错误后断开，防止无限连接耗尽资源 */
    private static final int MAX_CONNECTIONS = 20;
    /** 单会话最多读取的命令数：防止扫描器以命令流长期占用连接 */
    private static final int MAX_COMMANDS = 8;
    /** 命令参数个数/长度上限：防止畸形命令耗尽内存 */
    private static final int MAX_ARG_COUNT = 16;
    private static final int MAX_ARG_LENGTH = 1024;

    private final int port;
    private final AttackLogger logger;
    /** 虚拟线程执行器：每个连接一条虚拟线程 */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    /** 当前活跃连接数：原子计数，超过 {@link #MAX_CONNECTIONS} 的新连接立即拒绝 */
    private final AtomicInteger activeConnections = new AtomicInteger();
    private volatile boolean running = true;
    private ServerSocket serverSocket;

    public RedisHoneypotServer(int port, AttackLogger logger) {
        this.port = port;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        LOG.info("Redis 蜜罐已启动，监听端口 " + port + "（伪装版本 7，最大并发连接 " + MAX_CONNECTIONS + "）");
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

    /** 读取命令诱导客户端提交 AUTH 凭证，无论凭证是什么一律返回认证失败后断开 */
    private void handleClient(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        String sessionId = logger.newSessionId();
        logger.sessionOpen(sessionId, "redis", ip, socket.getPort());
        long start = System.currentTimeMillis();
        // 并发连接限流：先原子递增再判断，超限立即回退计数并按 Redis 标准返回超限错误后断开，
        // 避免恶意客户端无限建连耗尽服务器资源（先递增后判断保证并发下不超限）
        if (activeConnections.incrementAndGet() > MAX_CONNECTIONS) {
            activeConnections.decrementAndGet();
            try (socket) {
                write(socket.getOutputStream(), RESP_TOO_MANY);
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
            OutputStream out = socket.getOutputStream();
            // 诱导提交凭证：非认证命令按真实 Redis 回 -NOAUTH，等待客户端提交 AUTH
            for (int i = 0; i < MAX_COMMANDS; i++) {
                String[] cmd = readCommand(in);
                if (cmd == null || cmd.length == 0) break;
                switch (cmd[0].toUpperCase(Locale.ROOT)) {
                    case "AUTH" -> {
                        if (cmd.length == 2) {                  // AUTH <password>：Redis 6+ 按默认用户认证
                            capture(sessionId, ip, DEFAULT_USER, cmd[1]);
                            write(out, RESP_WRONGPASS);
                            return;
                        }
                        if (cmd.length >= 3) {                  // AUTH <username> <password>
                            capture(sessionId, ip, cmd[1], cmd[2]);
                            write(out, RESP_WRONGPASS);
                            return;
                        }
                        write(out, RESP_AUTH_ARGS);
                    }
                    case "HELLO" -> {
                        int ai = argIndex(cmd, "AUTH");         // HELLO [protover [AUTH <user> <pass>]]
                        if (ai >= 0 && ai + 2 < cmd.length) {
                            capture(sessionId, ip, cmd[ai + 1], cmd[ai + 2]);
                            write(out, RESP_WRONGPASS);
                            return;
                        }
                        write(out, RESP_NOAUTH);
                    }
                    case "QUIT" -> {
                        write(out, RESP_OK);
                        return;
                    }
                    default -> write(out, RESP_NOAUTH);
                }
            }
        } catch (SocketTimeoutException | EOFException e) {
            // 扫描器未发送命令或客户端提前断开：静默忽略
        } catch (IOException e) {
            // I/O 异常：静默忽略
        } finally {
            activeConnections.decrementAndGet();
            logger.sessionClose(sessionId, ip, System.currentTimeMillis() - start);
        }
    }

    /** 记录登录尝试（协议传输为明文凭证）；空密码记为 (空) */
    private void capture(String sessionId, String ip, String username, String password) {
        logger.authAttempt(sessionId, "redis", ip, username,
                password.isEmpty() ? "(空)" : password, false);
    }

    /**
     * 读取一条命令，兼容 RESP 数组（*N\r\n$len\r\n…）与内联命令（AUTH user pass\r\n）两种形式。
     * 返回参数数组；EOF/畸形报文返回 null（调用方直接断开）。
     */
    private static String[] readCommand(DataInputStream in) throws IOException {
        int first = in.read();
        if (first == -1) return null;
        if (first == '*') {                                     // RESP 数组
            int count = readLineInt(in);
            if (count <= 0 || count > MAX_ARG_COUNT) return null;
            String[] args = new String[count];
            for (int i = 0; i < count; i++) {
                if (in.read() != '$') return null;
                int len = readLineInt(in);
                if (len < 0 || len > MAX_ARG_LENGTH) return null;
                byte[] data = new byte[len];
                in.readFully(data);
                in.read();                                      // 参数尾部 \r
                in.read();                                      // 参数尾部 \n
                args[i] = new String(data, StandardCharsets.UTF_8);
            }
            return args;
        }
        // 内联命令：读取至行尾后按空白切分
        StringBuilder sb = new StringBuilder().append((char) first);
        int c;
        while ((c = in.read()) != -1 && c != '\n') {
            if (sb.length() >= MAX_ARG_LENGTH) return null;
            if (c != '\r') sb.append((char) c);
        }
        String line = sb.toString().trim();
        return line.isEmpty() ? new String[0] : line.split("\\s+");
    }

    /** 从参数列表下标 1 起查找指定名称的参数，返回下标；未找到返回 -1 */
    private static int argIndex(String[] cmd, String name) {
        for (int i = 1; i < cmd.length; i++) {
            if (cmd[i].equalsIgnoreCase(name)) return i;
        }
        return -1;
    }

    /** 读取一个以 CRLF 结尾的整数行（长度行），格式非法时抛出 I/O 异常 */
    private static int readLineInt(DataInputStream in) throws IOException {
        StringBuilder sb = new StringBuilder(8);
        int c;
        while ((c = in.read()) != -1 && c != '\n') {
            if (c != '\r') {
                if (sb.length() >= 32) throw new IOException("RESP 长度行过长");
                sb.append((char) c);
            }
        }
        if (c == -1) throw new EOFException();
        try {
            return Integer.parseInt(sb.toString());
        } catch (NumberFormatException e) {
            throw new IOException("非法 RESP 长度: " + sb);
        }
    }

    private static void write(OutputStream out, byte[] resp) throws IOException {
        out.write(resp);
        out.flush();
    }
}
