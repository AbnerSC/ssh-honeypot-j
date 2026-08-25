package org.open.scdm.honeypot.web;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 系统用户仓库：Web 控制台账号的增删改查与口令校验。
 * <p>
 * 与攻击日志共用同一 SQLite 文件（sys_users 表，WAL 模式下与蜜罐写入互不阻塞）。
 * 口令以 PBKDF2-HMAC-SHA256 加盐哈希存储，格式 pbkdf2-sha256$迭代次数$salt$hash。
 */
public class UserRepository implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(UserRepository.class.getName());
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static final String ROLE_ADMIN = "admin";    // 管理员：全部权限
    public static final String ROLE_VIEWER = "viewer";  // 只读：仅查看日志统计与明细

    private static final String DEFAULT_ADMIN = "admin";
    private static final String DEFAULT_ADMIN_PASSWORD = "admin123";

    private final Connection conn;

    public UserRepository(Path dbFile) throws SQLException {
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile.toAbsolutePath());
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA busy_timeout=5000");
            st.execute("PRAGMA cache_size=-600"); // 页缓存收紧至约 600KB，降低常驻原生内存
            st.execute("""
                    CREATE TABLE IF NOT EXISTS sys_users (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        username      TEXT    NOT NULL UNIQUE,          -- 登录用户名
                        password_hash TEXT    NOT NULL,                 -- PBKDF2 口令哈希
                        role          TEXT    NOT NULL DEFAULT 'admin', -- admin / viewer
                        status        INTEGER NOT NULL DEFAULT 1,       -- 1 启用 / 0 禁用
                        must_change   INTEGER NOT NULL DEFAULT 0,       -- 1 下次登录强制改密
                        created_at    TEXT    NOT NULL,
                        last_login_at TEXT
                    )""");
        }
        bootstrapDefaultAdmin();
    }

    /** 首次部署无任何账号时自动创建默认管理员（强制首次改密），避免控制台不可用 */
    private void bootstrapDefaultAdmin() throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM sys_users")) {
            if (rs.next() && rs.getInt(1) > 0) return;
        }
        createUser(DEFAULT_ADMIN, DEFAULT_ADMIN_PASSWORD, ROLE_ADMIN, true);
        LOG.warning("Web 控制台已创建默认管理员 " + DEFAULT_ADMIN + "/" + DEFAULT_ADMIN_PASSWORD
                + "（首次登录强制修改密码），请尽快修改！");
    }

    // ============================ 查询 ============================

    /** 按用户名查找（含口令哈希，仅供登录校验用）；不存在返回 null */
    Map<String, Object> findByUsername(String username) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, username, password_hash, role, status, must_change, created_at, last_login_at"
                        + " FROM sys_users WHERE username = ?")) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? readUser(rs, true) : null;
            }
        }
    }

    public Map<String, Object> findById(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, username, password_hash, role, status, must_change, created_at, last_login_at"
                        + " FROM sys_users WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? readUser(rs, false) : null;
            }
        }
    }

    /** 账号列表（不含口令哈希） */
    public List<Map<String, Object>> listUsers() throws SQLException {
        List<Map<String, Object>> list = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT id, username, password_hash, role, status, must_change, created_at, last_login_at"
                             + " FROM sys_users ORDER BY id")) {
            while (rs.next()) list.add(readUser(rs, false));
        }
        return list;
    }

    private static Map<String, Object> readUser(ResultSet rs, boolean withHash) throws SQLException {
        Map<String, Object> u = new LinkedHashMap<>();
        u.put("id", rs.getLong(1));
        u.put("username", rs.getString(2));
        if (withHash) u.put("passwordHash", rs.getString(3));
        u.put("role", rs.getString(4));
        u.put("enabled", rs.getInt(5) == 1);
        u.put("mustChange", rs.getInt(6) == 1);
        u.put("createdAt", rs.getString(7));
        u.put("lastLoginAt", rs.getString(8));
        return u;
    }

    // ============================ 写入 ============================

    public long createUser(String username, String password, String role, boolean mustChange) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO sys_users(username, password_hash, role, status, must_change, created_at)"
                        + " VALUES(?,?,?,?,?,?)", Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, username);
            ps.setString(2, Passwords.hash(password));
            ps.setString(3, role);
            ps.setInt(4, 1);
            ps.setInt(5, mustChange ? 1 : 0);
            ps.setString(6, LocalDateTime.now().format(TS));
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                return keys.next() ? keys.getLong(1) : -1;
            }
        }
    }

    public boolean setStatus(long id, boolean enabled) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("UPDATE sys_users SET status = ? WHERE id = ?")) {
            ps.setInt(1, enabled ? 1 : 0);
            ps.setLong(2, id);
            return ps.executeUpdate() > 0;
        }
    }

    public boolean resetPassword(long id, String newPassword, boolean mustChange) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE sys_users SET password_hash = ?, must_change = ? WHERE id = ?")) {
            ps.setString(1, Passwords.hash(newPassword));
            ps.setInt(2, mustChange ? 1 : 0);
            ps.setLong(3, id);
            return ps.executeUpdate() > 0;
        }
    }

    /** 修改口令并清除强制改密标记（自助改密与管理员重置共用） */
    public boolean changePassword(long id, String newPassword) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE sys_users SET password_hash = ?, must_change = 0 WHERE id = ?")) {
            ps.setString(1, Passwords.hash(newPassword));
            ps.setLong(2, id);
            return ps.executeUpdate() > 0;
        }
    }

    public boolean deleteUser(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("DELETE FROM sys_users WHERE id = ?")) {
            ps.setLong(1, id);
            return ps.executeUpdate() > 0;
        }
    }

    public long countAdmins() throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM sys_users WHERE role = 'admin' AND status = 1")) {
            return rs.next() ? rs.getLong(1) : 0;
        }
    }

    public void recordLogin(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE sys_users SET last_login_at = ? WHERE id = ?")) {
            ps.setString(1, LocalDateTime.now().format(TS));
            ps.setLong(2, id);
            ps.executeUpdate();
        }
    }

    @Override
    public void close() throws SQLException {
        conn.close();
    }

    /** PBKDF2-HMAC-SHA256 口令哈希工具（JDK 内置实现，无额外依赖） */
    public static final class Passwords {
        private static final int ITERATIONS = 210_000;
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;
        /** 盐生成器单例：SecureRandom 实例化需从系统熵源初始化，复用避免每次哈希重建 */
        private static final SecureRandom RANDOM = new SecureRandom();

        public static String hash(String password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] key = pbkdf2(password.toCharArray(), salt, ITERATIONS);
            return "pbkdf2-sha256$" + ITERATIONS + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(key);
        }

        public static boolean verify(String password, String stored) {
            if (stored == null) return false;
            String[] parts = stored.split("\\$");
            if (parts.length != 4 || !"pbkdf2-sha256".equals(parts[0])) return false;
            try {
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = Base64.getDecoder().decode(parts[2]);
                byte[] expected = Base64.getDecoder().decode(parts[3]);
                byte[] actual = pbkdf2(password.toCharArray(), salt, iterations);
                if (actual.length != expected.length) return false;
                int diff = 0;
                for (int i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
                return diff == 0; // 常数时间比较，防时序侧信道
            } catch (Exception e) {
                return false;
            }
        }

        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
            try {
                KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException("PBKDF2 计算失败", e);
            }
        }
    }
}
