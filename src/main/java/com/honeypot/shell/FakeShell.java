package com.honeypot.shell;

import com.honeypot.log.AttackLogger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * 交互式伪 Shell：实现行编辑（回显、退格、上下翻历史、Ctrl-C/Ctrl-D），
 * 并把输入交给 CommandProcessor。SSH 与 Telnet 两个协议共用这一个实现。
 */
public class FakeShell {
    private static final byte CR = 13, LF = 10, BS = 8, DEL = 127, CTRL_C = 3, CTRL_D = 4, ESC = 27;
    private static final int IAC = 0xFF, SB = 0xFA, SE = 0xF0;

    private final InputStream in;
    private final OutputStream out;
    private final SessionState state;
    private final CommandProcessor processor;
    private final AttackLogger logger;
    private final Consumer<SessionState> onExit;   // 会话结束回调（协议层负责关闭连接）

    private volatile boolean running = true;
    private final List<String> historyNav = new ArrayList<>();
    private int historyIdx = -1;
    private boolean pendingLF = false;   // 上一行以 \r 结束，下一个 \n 需要吞掉

    public FakeShell(InputStream in, OutputStream out, SessionState state,
                     CommandProcessor processor, AttackLogger logger, Consumer<SessionState> onExit) {
        this.in = in;
        this.out = out;
        this.state = state;
        this.processor = processor;
        this.logger = logger;
        this.onExit = onExit;
    }

    public void stop() {
        running = false;
    }

    /** 主循环（阻塞），应在独立线程中调用 */
    public void run() {
        long start = System.currentTimeMillis();
        try {
            printBanner();
            while (running) {
                write(state.prompt());
                String line = readLine();
                if (line == null) break;             // Ctrl-D 或连接断开
                pushHistory(line);
                String result = processor.execute(state, line);
                if (CommandProcessor.EXIT_SIGNAL.equals(result)) break;
                write(result.replace("\u0000NONL", ""));
            }
        } catch (IOException e) {
            // 攻击者断开连接，正常情况
        } finally {
            running = false;
            logger.sessionClose(state.sessionId, state.ip, System.currentTimeMillis() - start);
            try { onExit.accept(state); } catch (Exception ignored) {}
        }
    }

    private void printBanner() throws IOException {
        write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n" +
              " * Documentation:  https://help.ubuntu.com\r\n" +
              " * Management:     https://landscape.canonical.com\r\n" +
              " * Support:        https://ubuntu.com/advantage\r\n\r\n" +
              "Last login: Mon Aug 11 06:25:01 2026 from 203.0.113.44\r\n");
    }

    /* ------------------------------------------------------------------ */
    /* 行编辑器                                                            */
    /* ------------------------------------------------------------------ */

    private int read() throws IOException {
        return in.read();
    }

    /** 读取一行，处理回显/退格/历史。返回 null 表示会话结束。 */
    private String readLine() throws IOException {
        StringBuilder buf = new StringBuilder();
        while (running) {
            int b = read();
            if (b == -1) return null;

            if (b == IAC) { handleTelnetCommand(); continue; }
            if (b == ESC) { handleEscape(buf); continue; }

            if (b == CR) { pendingLF = true; writeRaw("\r\n"); break; }
            if (b == LF) {
                if (pendingLF) { pendingLF = false; continue; } // 吞掉 \r\n 残留的 \n
                writeRaw("\r\n");
                break;
            }
            pendingLF = false;

            if (b == BS || b == DEL) {
                if (buf.length() > 0) {
                    buf.setLength(buf.length() - 1);
                    writeRaw("\b \b");
                }
                continue;
            }
            if (b == CTRL_C) {
                writeRaw("^C\r\n");
                return "";
            }
            if (b == CTRL_D) {
                if (buf.length() == 0) return null;   // 空行按 Ctrl-D = 登出
                continue;
            }
            if (b < 0x20) continue;                   // 忽略其它控制字符

            buf.append((char) b);
            writeRawByte(b);                          // 回显
        }
        return buf.toString();
    }

    /** 历史导航（上/下箭头），其余转义序列直接吞掉 */
    private void handleEscape(StringBuilder buf) throws IOException {
        int b1 = read();
        if (b1 != '[' && b1 != 'O') return;
        int b2 = read();
        String target = null;
        if (b2 == 'A') {                              // 上箭头
            if (historyNav.isEmpty()) return;
            if (historyIdx == -1) historyIdx = historyNav.size() - 1;
            else if (historyIdx > 0) historyIdx--;
            target = historyNav.get(historyIdx);
        } else if (b2 == 'B') {                       // 下箭头
            if (historyIdx == -1) return;
            if (historyIdx < historyNav.size() - 1) {
                historyIdx++;
                target = historyNav.get(historyIdx);
            } else {
                historyIdx = -1;
                target = "";
            }
        } else {
            // 左右箭头/Delete/Home/End 等：吞掉序列尾部，忽略
            while (b2 >= 0x30 && b2 <= 0x3F) b2 = read();
            return;
        }
        // 重绘当前行：回车 + 提示符 + 新内容 + 清到行尾
        buf.setLength(0);
        buf.append(target);
        writeRaw("\r" + state.prompt() + target + "\033[K");
    }

    /** 吞掉 Telnet IAC 协商序列（出现在数据流中间的情况） */
    private void handleTelnetCommand() throws IOException {
        int cmd = read();
        if (cmd == -1) return;
        if (cmd >= 0xFB && cmd <= 0xFE) {             // WILL/WONT/DO/DONT
            read();
        } else if (cmd == SB) {                       // 子协商：读到 IAC SE
            int prev = -1, cur;
            while ((cur = read()) != -1) {
                if (prev == IAC && cur == SE) break;
                prev = cur;
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* 输出                                                                */
    /* ------------------------------------------------------------------ */

    private void write(String s) throws IOException {
        if (s == null || s.isEmpty()) return;
        // 终端需要 \r\n
        String normalized = s.replace("\r\n", "\n").replace("\n", "\r\n");
        out.write(normalized.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private void writeRaw(String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private void writeRawByte(int b) throws IOException {
        out.write(b);
        out.flush();
    }

    /** 记录已完成的命令供历史导航使用 */
    public void pushHistory(String line) {
        if (!line.isBlank()) {
            historyNav.add(line);
            historyIdx = -1;
        }
    }
}
