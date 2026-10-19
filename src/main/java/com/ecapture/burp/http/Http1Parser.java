package com.ecapture.burp.http;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Incremental parser for the HTTP/1.x plaintext stream of one direction of a TLS
 * connection ("write" side yields requests, "read" side yields responses).
 *
 * <p>Feed bytes as they arrive from eCapture (SSL_write/SSL_read chunks of up to 16 KB
 * each); complete messages are emitted through the callback, headers are parsed as soon
 * as the head terminator arrives and bodies are consumed per Content-Length or chunked
 * framing, progressively across chunk boundaries. A response without Content-Length and
 * without chunked encoding is emitted at head-parsed time and its body is appended
 * incrementally; it is finalized when {@link #close()} is called.
 */
public final class Http1Parser {

    public interface Callback {
        /** Emitted as soon as the head is parsed. */
        void onMessage(Message msg);

        /** Progressive body data for an open-ended response message. */
        void onBody(Message msg, byte[] data);

        /** Emitted exactly once per message when it is complete. */
        void onFinal(Message msg);
    }

    public static final class Header {
        public final String name;
        public final String value;

        Header(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    public static final class Message {
        public String kind; // "request" | "response"
        public String startLine = "";
        public final List<Header> headers = new ArrayList<>();
        public byte[] body = new byte[0];
        /** true when headers were emitted but body may still grow (read-to-close). */
        public boolean openEnded = false;
        public boolean complete = false;

        public String method() {
            if (!"request".equals(kind) || startLine.isEmpty()) return "";
            int sp = startLine.indexOf(' ');
            return sp > 0 ? startLine.substring(0, sp) : "";
        }

        public String path() {
            if (!"request".equals(kind) || startLine.isEmpty()) return "";
            int a = startLine.indexOf(' ');
            int b = startLine.lastIndexOf(' ');
            if (a < 0 || b <= a) return "?";
            return startLine.substring(a + 1, b);
        }

        public int statusCode() {
            if (!"response".equals(kind)) return -1;
            String[] p = startLine.split(" ");
            if (p.length < 2) return -1;
            try {
                return Integer.parseInt(p[1]);
            } catch (NumberFormatException e) {
                return -1;
            }
        }

        public String header(String nameLower) {
            for (Header h : headers) {
                if (h.name.equalsIgnoreCase(nameLower)) return h.value;
            }
            return null;
        }

        /** First-line summary for the table. */
        public String summary() {
            if ("request".equals(kind)) {
                return (method() + " " + path()).trim();
            }
            String sc = "";
            int first = startLine.indexOf(' ');
            if (first >= 0) sc = startLine.substring(first + 1);
            return sc;
        }

        public String contentType() {
            String ct = header("content-type");
            return ct == null ? "" : ct;
        }

        /** Rebuilds the raw bytes of this message (head + body) as they appeared. */
        public byte[] raw() {
            StringBuilder sb = new StringBuilder(256);
            sb.append(startLine).append("\r\n");
            for (Header h : headers) {
                sb.append(h.name).append(": ").append(h.value).append("\r\n");
            }
            sb.append("\r\n");
            byte[] headB = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
            byte[] out = new byte[headB.length + body.length];
            System.arraycopy(headB, 0, out, 0, headB.length);
            System.arraycopy(body, 0, out, headB.length, body.length);
            return out;
        }
    }

    private static final int ST_HEAD = 0;
    private static final int ST_BODY_CL = 1;
    private static final int ST_BODY_CHUNK_SIZE = 2;
    private static final int ST_BODY_CHUNK_DATA = 3;
    private static final int ST_BODY_CHUNK_CRLF = 4;
    private static final int ST_BODY_TRAILERS = 5;
    private static final int ST_BODY_OPEN = 6;
    private static final int ST_FAILED = 7;

    private static final int MAX_HEAD = 512 * 1024;
    private static final long MAX_BODY = 32L << 20;

    private final Callback cb;
    private final boolean requestSide;
    private int stage = ST_HEAD;
    private final ByteArrayOutputStream head = new ByteArrayOutputStream(1024);
    private Message current;
    private long bodyNeeded = 0;
    private long bodySeen = 0;
    private long chunkRemaining = 0;
    private ByteArrayOutputStream line = new ByteArrayOutputStream(64);
    private String lastLine = null;

    public Http1Parser(boolean requestSide, Callback cb) {
        this.requestSide = requestSide;
        this.cb = cb;
    }

    public boolean failed() {
        return stage == ST_FAILED;
    }

    /** Feed more plaintext bytes. Tolerates subsequent calls with split terminators. */
    public synchronized boolean feed(byte[] data, int off, int len) {
        if (stage == ST_FAILED) return false;
        int i = off;
        int stop = off + len;
        try {
            while (i < stop && stage != ST_FAILED) {
                switch (stage) {
                    case ST_HEAD: {
                        head.write(data, i, stop - i);
                        i = stop;
                        if (head.size() > MAX_HEAD) {
                            fail();
                            return false;
                        }
                        byte[] acc = head.toByteArray();
                        // tolerate stray blank lines between messages
                        int lead = 0;
                        while (acc.length - lead >= 4 && acc[lead] == '\r' && acc[lead + 1] == '\n'
                            && acc[lead + 2] == '\r' && acc[lead + 3] == '\n') {
                            lead += 4;
                        }
                        int t = findHeadEnd(acc, lead);
                        if (t < 0) {
                            break; // need more bytes
                        }
                        head.reset();
                        int headLen = t - lead;
                        if (headLen > 0) {
                            byte[] headBytes = new byte[headLen];
                            System.arraycopy(acc, lead, headBytes, 0, headLen);
                            if (!parseHead(headBytes)) {
                                fail();
                                return false;
                            }
                        }
                        // re-process any body bytes that arrived in this same chunk
                        if (acc.length > t + 4 && stage != ST_FAILED) {
                            boolean ok2 = feed(acc, t + 4, acc.length - t - 4); // reentrant call; stage changed
                            if (!ok2) {
                                return false;
                            }
                        }
                        break;
                    }
                    case ST_BODY_CL: {
                        long take = Math.min(bodyNeeded - bodySeen, (long) (stop - i));
                        if (current != null && !current.complete && take > 0) {
                            current.body = append(current.body, data, i, (int) take);
                        }
                        bodySeen += take;
                        i += take;
                        if (bodySeen >= bodyNeeded) {
                            stage = ST_HEAD;
                            finishBody();
                        }
                        break;
                    }
                    case ST_BODY_CHUNK_SIZE: {
                        if (!readLine(data, i, stop)) { i = stop; break; }
                        i += consumed;
                        String sz = lastLine == null ? "" : lastLine;
                        lastLine = null;
                        int semi = sz.indexOf(';');
                        String hex = semi >= 0 ? sz.substring(0, semi) : sz;
                        long n;
                        try {
                            n = Long.parseLong(hex.trim(), 16);
                        } catch (NumberFormatException e) {
                            fail();
                            return false;
                        }
                        if (n == 0) {
                            stage = ST_BODY_TRAILERS;
                        } else {
                            chunkRemaining = n;
                            stage = ST_BODY_CHUNK_DATA;
                        }
                        break;
                    }
                    case ST_BODY_CHUNK_DATA: {
                        long take = Math.min(chunkRemaining, stop - i);
                        if (current != null && !current.complete && take > 0) {
                            current.body = append(current.body, data, i, (int) take);
                            if (current.body.length > MAX_BODY) {
                                fail();
                                return false;
                            }
                        }
                        chunkRemaining -= take;
                        i += take;
                        if (chunkRemaining == 0) {
                            stage = ST_BODY_CHUNK_CRLF;
                        }
                        break;
                    }
                    case ST_BODY_CHUNK_CRLF: {
                        if (i + 2 > stop) {
                            i = stop;
                            break;
                        }
                        if (data[i] == '\r' && data[i + 1] == '\n') {
                            i += 2;
                            stage = ST_BODY_CHUNK_SIZE;
                        } else {
                            fail();
                            return false;
                        }
                        break;
                    }
                    case ST_BODY_TRAILERS: {
                        if (!readLine(data, i, stop)) { i = stop; break; }
                        i += consumed;
                        String l = lastLine == null ? "" : lastLine;
                        lastLine = null;
                        if (l.isEmpty()) {
                            stage = ST_HEAD;
                            finishBody();
                        }
                        break;
                    }
                    case ST_BODY_OPEN: {
                        if (current != null && !current.complete) {
                            byte[] chunk = slice(data, i, stop - i);
                            current.body = append(current.body, chunk, 0, chunk.length);
                            cb.onBody(current, chunk);
                            if (current.body.length >= MAX_BODY) {
                                close();
                            }
                        }
                        i = stop;
                        break;
                    }
                    case ST_FAILED:
                    default:
                        return false;
                }
            }
            return stage != ST_FAILED;
        } catch (Throwable t) {
            fail();
            return false;
        }
    }

    private int consumed = 0;

    private boolean readLine(byte[] data, int i, int stop) {
        int j = i;
        while (j < stop) {
            byte b = data[j++];
            line.write(b);
            int n = line.size();
            if (n >= 2) {
                byte[] acc = line.toByteArray();
                if (acc[n - 2] == '\r' && acc[n - 1] == '\n') {
                    lastLine = new String(acc, 0, n - 2, StandardCharsets.ISO_8859_1);
                    line.reset();
                    consumed = j - i;
                    if (lastLine.length() > 131072) {
                        fail();
                        return false;
                    }
                    return true;
                }
            }
        }
        consumed = j - i;
        if (line.size() > 131072) {
            fail();
            return false;
        }
        return false;
    }

    /** Ends a read-to-close response (called when the connection definitely has no more data). */
    public synchronized void close() {
        if (stage == ST_BODY_OPEN && current != null && current.openEnded && !current.complete) {
            current.complete = true;
            current.openEnded = false;
            cb.onFinal(current);
            current = null;
        }
    }

    private void finishBody() {
        if (current != null && !current.complete) {
            current.complete = true;
            cb.onFinal(current);
            current = null;
        }
    }

    private void fail() {
        stage = ST_FAILED;
        current = null;
        head.reset();
    }

    private boolean parseHead(byte[] headBytes) {
        String text = new String(headBytes, StandardCharsets.ISO_8859_1);
        Message m = new Message();
        String[] lines = text.split("\r\n");
        m.startLine = lines.length > 0 ? lines[0] : "";
        if (requestSide) {
            m.kind = "request";
            if (!m.startLine.matches("(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|MKCOL|MOVE|COPY|LOCK|UNLOCK) \\S+ HTTP/\\d(\\.\\d)+")) {
                return false;
            }
        } else {
            m.kind = "response";
            if (!m.startLine.startsWith("HTTP/1.") || m.startLine.length() < 12) {
                return false;
            }
        }
        long contentLength = -1;
        boolean chunked = false;
        for (int k = 1; k < lines.length; k++) {
            int c = lines[k].indexOf(':');
            if (c <= 0) return false;
            String name = lines[k].substring(0, c).trim();
            String value = lines[k].substring(c + 1).trim();
            m.headers.add(new Header(name, value));
            if (name.equalsIgnoreCase("Content-Length")) {
                try {
                    contentLength = Long.parseLong(value.trim());
                } catch (NumberFormatException e) {
                    contentLength = -1;
                }
            } else if (name.equalsIgnoreCase("Transfer-Encoding") && value.toLowerCase().contains("chunked")) {
                chunked = true;
            }
        }
        current = m;
        if (contentLength >= 0) {
            stage = ST_BODY_CL;
            bodyNeeded = contentLength;
            bodySeen = 0;
            if (bodyNeeded == 0) {
                stage = ST_HEAD;
                finishBody();
            }
        } else if (chunked) {
            stage = ST_BODY_CHUNK_SIZE;
        } else if (requestSide) {
            stage = ST_HEAD;
            finishBody();
        } else {
            m.openEnded = true;
            m.body = new byte[0];
            stage = ST_BODY_OPEN;
            cb.onMessage(m);
        }
        return true;
    }

    private static int findHeadEnd(byte[] acc, int from) {
        int n = acc.length;
        if (n < 4) return -1;
        // search for \r\n\r\n starting at or after `from`
        for (int i = Math.max(from, 0); i <= n - 4; i++) {
            if (acc[i] == '\r' && acc[i + 1] == '\n' && acc[i + 2] == '\r' && acc[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static byte[] append(byte[] body, byte[] src, int off, int len) {
        byte[] joined = new byte[body.length + len];
        System.arraycopy(body, 0, joined, 0, body.length);
        System.arraycopy(src, off, joined, body.length, len);
        return joined;
    }

    private static byte[] slice(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }
}
