package com.ecapture.burp;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ecapture.burp.pb.LogEntry;

/**
 * Adapts pre-v2.8 eCaptureQ events (e.g. ecapture v2.7.0) to the typed form the engine expects.
 *
 * <p>Before v2.8.0, {@code --ecaptureq} sent each captured event as only {@code payload}: the text
 * handler's rendering of the event, with no pid/tuple/direction fields. TLS data events look like
 * {@code [2026-10-19 15:48:00.285] PID:5539 TID:6047 Comm:x FD:1 WRITE (1804 bytes):\n<data>\n}
 * and OpenSSL connection events like {@code PID:5539, Comm:x, TID:6047, FD:1, Tuple: a:1->b:2}.
 * Connection events are remembered so later data events on the same pid/fd get their addresses.
 */
final class LegacyTextEvents {

    private static final Pattern DATA_HEADER = Pattern.compile(
        "^\\[[^\\]]*\\] PID:(\\d+) TID:\\d+ Comm:(.*?) FD:(-?\\d+) (READ|WRITE) \\((\\d+) bytes(, hex)?\\):$");
    private static final Pattern CONN_LINE = Pattern.compile(
        "^PID:(\\d+), Comm:(.*?), TID:\\d+, FD:(-?\\d+), Tuple: (\\S+)->(\\S+)\\s*$");
    private static final int MAX_HEADER = 512;
    private static final int MAX_TUPLES = 4096;

    /** pid#fd -> {local ip, local port, remote ip, remote port}. */
    private final HashMap<String, String[]> tuples = new HashMap<>();

    /** True for an event from a pre-v2.8 server: no capture_format, payload is rendered text. */
    static boolean isLegacy(LogEntry.EventBus ev) {
        return ev.captureFormat == 0 && ev.direction.isEmpty() && ev.pid == 0;
    }

    /**
     * Returns the typed equivalent of a legacy data event, or null when the event carries no
     * HTTP plaintext (connection records, hex dumps, keylog lines, unrecognised output).
     */
    LogEntry.EventBus convert(LogEntry.EventBus ev) {
        byte[] p = ev.payload;
        int nl = indexOf(p, (byte) '\n', Math.min(p.length, MAX_HEADER));
        String head = new String(p, 0, nl < 0 ? Math.min(p.length, MAX_HEADER) : nl,
            StandardCharsets.UTF_8);

        Matcher m = DATA_HEADER.matcher(head);
        if (nl >= 0 && m.matches()) {
            if (m.group(6) != null) return null; // --hex output is a dump, not the raw bytes
            int declared = Integer.parseInt(m.group(5));
            int start = nl + 1;
            // the text handler appends '\n' when the data does not end with one
            int len = Math.min(declared, p.length - start);
            if (len <= 0) return null;
            byte[] data = new byte[len];
            System.arraycopy(p, start, data, 0, len);

            LogEntry.EventBus out = new LogEntry.EventBus();
            out.captureFormat = 1;
            out.pid = Long.parseLong(m.group(1));
            out.pname = m.group(2);
            boolean read = "READ".equals(m.group(4));
            out.direction = read ? "read" : "write";
            out.payload = data;
            out.length = len;
            out.uuid = ev.uuid;
            out.timestamp = ev.timestamp;

            // Comm is the *thread* name, and OkHttp drives one HTTP/2 connection from several
            // threads, so a connection is identified by pid + fd only.
            out.connKey = out.pid + "#fd" + m.group(3);
            String[] t = tuples.get(out.pid + "#" + m.group(3));
            if (t == null) {
                t = new String[]{"", "0", "fd " + m.group(3), "0"};
            }
            if (read) {
                out.srcIp = t[2]; out.srcPort = Long.parseLong(t[3]);
                out.dstIp = t[0]; out.dstPort = Long.parseLong(t[1]);
            } else {
                out.srcIp = t[0]; out.srcPort = Long.parseLong(t[1]);
                out.dstIp = t[2]; out.dstPort = Long.parseLong(t[3]);
            }
            return out;
        }

        Matcher c = CONN_LINE.matcher(head.trim());
        if (c.matches()) {
            String[] local = splitAddr(c.group(4));
            String[] remote = splitAddr(c.group(5));
            if (local != null && remote != null && !"0".equals(remote[1])) {
                if (tuples.size() >= MAX_TUPLES) tuples.clear();
                tuples.put(c.group(1) + "#" + c.group(3),
                    new String[]{local[0], local[1], remote[0], remote[1]});
            }
        }
        return null;
    }

    /** "1.2.3.4:443", "[::1]:443" or "::ffff:1.2.3.4:443" -> {ip, port}. */
    static String[] splitAddr(String s) {
        int colon = s.lastIndexOf(':');
        if (colon <= 0 || colon == s.length() - 1) return null;
        String ip = s.substring(0, colon);
        String port = s.substring(colon + 1);
        if (!port.chars().allMatch(Character::isDigit)) return null;
        if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.substring(1, ip.length() - 1);
        return new String[]{ip, port};
    }

    private static int indexOf(byte[] data, byte b, int limit) {
        for (int i = 0; i < limit; i++) {
            if (data[i] == b) return i;
        }
        return -1;
    }
}
