package com.ecapture.burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.ecapture.burp.h2.HpackDecoder;
import com.ecapture.burp.h2.Http2Decoder;
import com.ecapture.burp.http.Http1Parser;
import com.ecapture.burp.pb.LogEntry;

/**
 * Turns eCaptureQ TLS plaintext events (per-SSL-chunk, per connection) into HTTP
 * messages: reassembles HTTP/1.x streams and decodes HTTP/2 connections.
 *
 * <p>Single-threaded by design: all entry points are invoked from the WebSocket
 * client thread in arrival order. The listener is called on that same thread and
 * must marshal work onto the Swing EDT itself.
 */
public final class AssembleEngine {

    public interface Listener {
        void onNewItem(CaptureItem item);

        void onUpdatedItem(CaptureItem item);
    }

    private static final long CONN_IDLE_MS = 15 * 60 * 1000L;
    private static final int MAX_CONNS = 512;
    private static final long MAX_BODY = 8L << 20;
    private static final int MAX_PENDING_H1 = 64;

    private static final String[] METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
        "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK"};

    private final Listener listener;
    private final LegacyTextEvents legacy = new LegacyTextEvents();
    private int nextId = 1;
    private final HashMap<String, Conn> conns = new HashMap<>();
    private final IdentityHashMap<Http1Parser.Message, CaptureItem> h1OpenResponses =
        new IdentityHashMap<>();

    public AssembleEngine(Listener listener) {
        this.listener = listener;
    }

    public void clear() {
        for (Conn c : conns.values()) {
            if (c.h1Req != null) c.h1Req.close();
            if (c.h1Resp != null) c.h1Resp.close();
        }
        conns.clear();
        h1OpenResponses.clear();
    }

    // ------------------------------------------------------------------ entry

    public synchronized void onEvent(LogEntry.EventBus ev) {
        if (ev == null) return;
        if (ev.payload == null || ev.payload.length == 0) return;
        if (LegacyTextEvents.isLegacy(ev)) {
            ev = legacy.convert(ev); // ecapture < v2.8 sends rendered text only
            if (ev == null) return;
        }
        byte[] payload = ev.payload;
        if (ev.captureFormat != 1) return; // only TEXT capture mode carries HTTP plaintext

        boolean read = "read".equalsIgnoreCase(ev.direction);
        String clientAddr = read ? tuple(ev.dstIp, ev.dstPort) : tuple(ev.srcIp, ev.srcPort);
        String serverAddr = read ? tuple(ev.srcIp, ev.srcPort) : tuple(ev.dstIp, ev.dstPort);
        String key = ev.connKey != null ? "L#" + ev.connKey
            : ev.pid + "#" + nvl(ev.pname) + "#" + clientAddr + "#" + serverAddr;

        Conn c = conns.get(key);
        if (c == null) {
            c = new Conn(key, ev.pid, nvl(ev.pname), clientAddr, serverAddr,
                System.currentTimeMillis());
            conns.put(key, c);
            evictIdle();
        } else {
            c.lastSeen = System.currentTimeMillis();
        }

        if (c.decided && startsNewStream(c, payload, read)) {
            resetConn(c); // fd reused for a new connection, or recovering from RAW
        }

        if (!c.decided) {
            decide(c, payload, read);
            if (c.isRaw) {
                rawChunk(c, ev, payload);
                return;
            }
        } else if (c.isRaw) {
            rawChunk(c, ev, payload);
            return;
        }

        if (c.isH2) {
            feedH2(c, payload, read);
        } else {
            feedH1(c, payload, read);
        }
    }

    /**
     * True when this chunk unmistakably begins a fresh stream that the connection's current
     * state cannot continue: an HTTP/2 preface on any connection not just started, or an
     * HTTP/1 request/status line on a connection that fell back to RAW.
     */
    private boolean startsNewStream(Conn c, byte[] chunk, boolean readSide) {
        if (!readSide && matchesPreface(chunk)) {
            return !(c.isH2 && c.h2Req == null);
        }
        if (!c.isRaw) return false;
        if (readSide) {
            return asciiHead(chunk, 9).startsWith("HTTP/1.");
        }
        String head = asciiHead(chunk, 32);
        for (String m : METHODS) {
            if (head.startsWith(m + " ")) return true;
        }
        return false;
    }

    private void resetConn(Conn c) {
        closeConn(c);
        h1OpenResponses.values().removeIf(it -> c.key.equals(it.connKey));
        c.h1Req = null;
        c.h1Resp = null;
        c.h2Req = null;
        c.h2Resp = null;
        c.h1Pending.clear();
        c.h2Streams.clear();
        c.h2Items.clear();
        c.decided = false;
        c.isH2 = false;
        c.isRaw = false;
    }

    private static String tuple(String ip, long port) {
        if (ip == null || ip.isEmpty()) return "?";
        if (port == 0 && ip.startsWith("fd ")) return ip;
        if (ip.contains(":") && !ip.startsWith("[")) return "[" + ip + "]:" + port;
        return ip + ":" + port;
    }

    private static String nvl(String s) {
        return s == null ? "" : s;
    }

    private void evictIdle() {
        if (conns.size() < MAX_CONNS) return;
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Conn>> it = conns.entrySet().iterator();
        while (it.hasNext()) {
            Conn c = it.next().getValue();
            if (now - c.lastSeen > CONN_IDLE_MS) {
                closeConn(c);
                it.remove();
            }
        }
        while (conns.size() >= MAX_CONNS) {
            String oldestKey = null;
            long oldest = Long.MAX_VALUE;
            for (Map.Entry<String, Conn> e : conns.entrySet()) {
                if (e.getValue().lastSeen < oldest) {
                    oldest = e.getValue().lastSeen;
                    oldestKey = e.getKey();
                }
            }
            if (oldestKey == null) break;
            closeConn(conns.remove(oldestKey));
        }
    }

    private void closeConn(Conn c) {
        if (c == null) return;
        if (c.h1Resp != null) c.h1Resp.close();
        if (c.h1Req != null) c.h1Req.close();
    }

    /** Protocol decision, lazily on the first chunk of a connection. */
    void decide(Conn c, byte[] chunk, boolean readSide) {
        c.decided = true;
        if (matchesPreface(chunk)) {
            c.isH2 = true;
            return;
        }
        if (readSide) {
            // mid-stream capture: server SETTINGS(0000 04 / 0006 04) or HTTP/1 status line
            boolean looksH2 = chunk.length >= 4 && chunk[0] == 0 && chunk[1] == 0
                && (chunk[2] == 0 || chunk[2] == 6)
                && (chunk[3] & 0xFF) == Http2Decoder.SETTINGS;
            if (looksH2) {
                c.isH2 = true;
            } else {
                c.isH2 = false; // HTTP/1 guess; falls back to raw on parse failure
            }
            return;
        }
        String head = asciiHead(chunk, 32);
        for (String m : METHODS) {
            if (head.startsWith(m + " ")) {
                c.isH2 = false;
                return;
            }
        }
        c.isRaw = true;
    }

    private boolean matchesPreface(byte[] chunk) {
        byte[] pre = Http2Decoder.CLIENT_PREFACE;
        if (chunk.length < pre.length) return false;
        for (int i = 0; i < pre.length; i++) {
            if (chunk[i] != pre[i]) return false;
        }
        return true;
    }

    private static String asciiHead(byte[] data, int n) {
        int len = Math.min(n, data.length);
        byte[] b = new byte[len];
        System.arraycopy(data, 0, b, 0, len);
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    // ------------------------------------------------------------------ RAW

    private void rawChunk(Conn c, LogEntry.EventBus ev, byte[] payload) {
        CaptureItem item = newItem(c, "RAW");
        item.rawRequest = payload;
        item.requestComplete = true;
        int len = Math.min(payload.length, MAX_TRAILING_TEXT);
        item.summary = "raw chunk (" + len + "/" + payload.length + " bytes)";
        listener.onNewItem(item);
    }

    private static final int MAX_TRAILING_TEXT = 64;

    private CaptureItem newItem(Conn c, String kind) {
        return new CaptureItem(nextId++, System.currentTimeMillis(), c.key, c.pid, c.pname,
            c.clientAddr, c.serverAddr, kind);
    }

    // ------------------------------------------------------------------ HTTP/1

    private void feedH1(final Conn c, byte[] chunk, boolean readSide) {
        if (readSide) {
            if (c.h1Resp == null) {
                c.h1Resp = new Http1Parser(false, new Http1Parser.Callback() {
                    @Override public void onMessage(Http1Parser.Message msg) {
                        h1ProvisionResponse(c, msg);
                    }

                    @Override public void onBody(Http1Parser.Message msg, byte[] data) {
                        h1BodyUpdate(c, msg);
                    }

                    @Override public void onFinal(Http1Parser.Message msg) {
                        h1Final(c, msg);
                    }
                });
            }
            boolean ok = c.h1Resp.feed(chunk, 0, chunk.length);
            if (!ok) {
                c.h1Resp = null;
                c.isRaw = true;
            }
        } else {
            if (c.h1Req == null) {
                c.h1Req = new Http1Parser(true, new Http1Parser.Callback() {
                    @Override public void onMessage(Http1Parser.Message msg) { /* handled at final */ }

                    @Override public void onBody(Http1Parser.Message msg, byte[] data) { /* n/a */ }

                    @Override public void onFinal(Http1Parser.Message msg) {
                        h1Final(c, msg);
                    }
                });
            }
            boolean ok = c.h1Req.feed(chunk, 0, chunk.length);
            if (!ok) {
                c.h1Req = null;
                c.isRaw = true;
            }
        }
    }

    private void h1ProvisionResponse(Conn c, Http1Parser.Message msg) {
        if ("request".equals(msg.kind)) return;
        CaptureItem item = newItem(c, "HTTP/1");
        item.status = msg.statusCode();
        item.contentType = msg.contentType();
        item.rawResponse = msg.raw();
        item.responseComplete = false;
        item.summary = msg.summary();
        h1OpenResponses.put(msg, item);
        listener.onNewItem(item);
    }

    private void h1BodyUpdate(Conn c, Http1Parser.Message msg) {
        CaptureItem item = h1OpenResponses.get(msg);
        if (item != null) {
            item.rawResponse = msg.raw();
            item.contentType = msg.contentType();
            listener.onUpdatedItem(item);
        }
    }

    /** A complete HTTP/1 message: request or response. */
    private void h1Final(final Conn c, Http1Parser.Message msg) {
        if ("request".equals(msg.kind)) {
            CaptureItem item = newItem(c, "HTTP/1");
            item.method = msg.method();
            item.path = msg.path();
            String host = msg.header("host");
            if (host != null && !host.isEmpty()) {
                item.host = host.toLowerCase();
            }
            item.contentType = msg.contentType();
            item.rawRequest = msg.raw();
            item.requestComplete = true;
            item.summary = msg.method() + " " + msg.path();
            c.h1Pending.addLast(item);
            while (c.h1Pending.size() > MAX_PENDING_H1) {
                c.h1Pending.removeFirst();
            }
            listener.onNewItem(item);
            return;
        }
        // response completed; flush any provisional open-ended row first
        CaptureItem provisional = h1OpenResponses.remove(msg);
        if (provisional != null) {
            provisional.rawResponse = msg.raw();
            provisional.status = msg.statusCode();
            provisional.contentType = msg.contentType();
            provisional.responseComplete = true;
            provisional.truncated = msg.body.length >= MAX_BODY;
            listener.onUpdatedItem(provisional);
            return;
        }
        // pair FIFO keep-alive order to the oldest request missing its response
        for (CaptureItem cand : c.h1Pending) {
            if (!cand.responseComplete) {
                cand.rawResponse = msg.raw();
                cand.status = msg.statusCode();
                cand.contentType = msg.contentType();
                cand.responseComplete = true;
                listener.onUpdatedItem(cand);
                c.h1Pending.remove(cand);
                return;
            }
        }
        // standalone response seen without its request (mid-stream capture)
        CaptureItem item = newItem(c, "HTTP/1");
        item.status = msg.statusCode();
        item.contentType = msg.contentType();
        item.rawResponse = msg.raw();
        item.responseComplete = true;
        item.truncated = msg.body.length >= MAX_BODY;
        item.summary = msg.summary();
        listener.onNewItem(item);
    }

    // ------------------------------------------------------------------ HTTP/2

    private void feedH2(Conn c, byte[] chunk, boolean readSide) {
        Http2Decoder dec;
        if (readSide) {
            if (c.h2Resp == null) {
                c.h2Resp = new Http2Decoder(false, new H2Handler(c, false));
            }
            dec = c.h2Resp;
        } else {
            if (c.h2Req == null) {
                c.h2Req = new Http2Decoder(true, new H2Handler(c, true));
            }
            dec = c.h2Req;
        }
        dec.feed(chunk, 0, chunk.length);
        if (dec.failed()) {
            c.isRaw = true;
            if (readSide) c.h2Resp = null; else c.h2Req = null;
        }
    }

    /** Per-stream state for one HTTP/2 direction. */
    private static final class H2Msg {
        Long streamId;
        List<HpackDecoder.HeaderField> headers = new ArrayList<>();
        List<HpackDecoder.HeaderField> trailers;
        byte[] body = new byte[0];
        boolean headDone;
        boolean isResponse;
        boolean push;
        boolean endStream;
        boolean finished;
        boolean truncated;
    }

    /** Connection-level HTTP/2 state. */
    private static final class Conn {
        final String key;
        final long pid;
        final String pname;
        final String clientAddr;
        final String serverAddr;
        long lastSeen;
        boolean decided;
        boolean isH2;
        boolean isRaw;
        Http1Parser h1Req;
        Http1Parser h1Resp;
        Http2Decoder h2Req;
        Http2Decoder h2Resp;
        final Deque<CaptureItem> h1Pending = new ArrayDeque<>();
        final Map<Long, H2Msg> h2Streams = new HashMap<>();
        final Map<Long, CaptureItem> h2Items = new HashMap<>();

        Conn(String key, long pid, String pname, String clientAddr, String serverAddr, long lastSeen) {
            this.key = key;
            this.pid = pid;
            this.pname = pname;
            this.clientAddr = clientAddr;
            this.serverAddr = serverAddr;
            this.lastSeen = lastSeen;
        }
    }

    private final class H2Handler implements Http2Decoder.Listener {
        private final Conn conn;
        private final boolean clientHalf; // true = decoder over the client→server half

        H2Handler(Conn conn, boolean clientHalf) {
            this.conn = conn;
            this.clientHalf = clientHalf;
        }

        private H2Msg getMsg(long streamId) {
            H2Msg m = conn.h2Streams.get(streamId);
            if (m == null) {
                m = new H2Msg();
                m.streamId = streamId;
                conn.h2Streams.put(streamId, m);
            }
            return m;
        }

        private void prune() {
            if (conn.h2Streams.size() > 512) {
                conn.h2Streams.clear();
            }
        }

        @Override public void onHeaders(long streamId, List<HpackDecoder.HeaderField> fields,
                                        boolean endStream, boolean push) {
            prune();
            if (push && clientHalf) {
                return; // push promises only ever appear on the server half
            }
            if (push) {
                handlePushPromise(streamId, fields);
                return;
            }
            H2Msg m = getMsg(streamId);
            if (m.headDone) {
                // trailers
                m.trailers = new ArrayList<>(fields);
                if (endStream) {
                    m.endStream = true;
                    finish(m);
                }
                return;
            }
            m.headers = new ArrayList<>(fields);
            m.isResponse = hasField(m.headers, ":status");
            m.headDone = true;
            if (endStream) {
                m.endStream = true;
                finish(m);
                return;
            }
            if (!m.isResponse && clientHalf) {
                provisionRequestRow(m);
            }
        }

        /** PUSH_PROMISE carries the pushed request; the response follows on that stream. */
        private void handlePushPromise(long streamId, List<HpackDecoder.HeaderField> fields) {
            CaptureItem item = conn.h2Items.get(streamId);
            if (item != null) return; // already handled
            item = newItem(conn, "PUSH");
            item.h2StreamId = streamId;
            H2Msg tmp = new H2Msg();
            tmp.streamId = streamId;
            tmp.headers = new ArrayList<>(fields);
            tmp.headDone = true;
            applyRequest(item, tmp);
            item.requestComplete = true;
            conn.h2Items.put(streamId, item);
            listener.onNewItem(item);
        }

        @Override public void onData(long streamId, byte[] data, boolean endStream) {
            prune();
            H2Msg m = getMsg(streamId);
            if (data != null && data.length > 0) {
                if (m.body.length + data.length > MAX_BODY) {
                    m.truncated = true;
                    m.endStream = true;
                } else {
                    m.body = append(m.body, data, 0, data.length);
                }
            }
            if (endStream) {
                m.endStream = true;
            }
            if (m.endStream && m.headDone) {
                finish(m);
            }
        }

        private H2Msg finish(H2Msg m) {
            if (m.finished) return m;
            if (!m.headDone) return m;
            m.finished = true;
            if (m.isResponse) {
                CaptureItem row = conn.h2Items.get(m.streamId);
                if (row != null) {
                    applyResponse(row, m);
                    row.responseComplete = true;
                    listener.onUpdatedItem(row);
                } else {
                    row = newItem(conn, "HTTP/2");
                    row.h2StreamId = m.streamId;
                    applyResponse(row, m);
                    row.responseComplete = true;
                    conn.h2Items.put(m.streamId, row);
                    listener.onNewItem(row);
                }
            } else {
                CaptureItem row = conn.h2Items.get(m.streamId);
                if (row == null) {
                    row = newItem(conn, "HTTP/2");
                    row.h2StreamId = m.streamId;
                    applyRequest(row, m);
                    conn.h2Items.put(m.streamId, row);
                    listener.onNewItem(row);
                } else {
                    applyRequest(row, m);
                    listener.onUpdatedItem(row);
                }
            }
            conn.h2Streams.remove(m.streamId);
            return m;
        }

        private void provisionRequestRow(H2Msg m) {
            if (conn.h2Items.get(m.streamId) != null) return;
            CaptureItem row = newItem(conn, "HTTP/2");
            row.h2StreamId = m.streamId;
            applyRequest(row, m);
            row.requestComplete = m.endStream;
            conn.h2Items.put(m.streamId, row);
            listener.onNewItem(row);
        }

        void applyRequest(CaptureItem item, H2Msg m) {
            String method = valOf(m.headers, ":method");
            String path = valOf(m.headers, ":path");
            String authority = valOf(m.headers, ":authority");
            item.method = method == null ? "" : method;
            item.path = path == null ? "/" : path;
            if (authority != null && !authority.isEmpty()) {
                item.host = stripPortKeep(authority);
            }
            item.contentType = orEmpty(valOf(m.headers, "content-type"));
            item.h2reqHeaders = headersAsArray(m.headers);
            item.h2reqBody = m.body;
            item.rawRequest = concatHeadBody(headText(m.headers,
                (method == null || method.isEmpty() ? "GET" : method) + " "
                    + (path == null || path.isEmpty() ? "/" : path) + " HTTP/2"), m.body);
            item.truncated |= m.truncated;
            if (item.summary.isEmpty()) {
                item.summary = item.method + " " + item.path;
            }
        }

        void applyResponse(CaptureItem item, H2Msg m) {
            String status = valOf(m.headers, ":status");
            item.status = parseStatus(status);
            item.contentType = orEmpty(valOf(m.headers, "content-type"));
            List<HpackDecoder.HeaderField> all = new ArrayList<>(m.headers);
            if (m.trailers != null) {
                all.addAll(m.trailers);
            }
            item.h2respHeaders = headersAsArray(all);
            item.h2respBody = m.body;
            item.rawResponse = concatHeadBody(headText(all,
                "HTTP/2 " + (item.status >= 0 ? item.status : 200)), m.body);
            item.truncated |= m.truncated;
            item.summary = item.summary.isEmpty()
                ? (item.path.isEmpty() ? "" : item.path + "  «") + (item.status >= 0 ? item.status : 0)
                : item.summary + "  «" + (item.status >= 0 ? item.status : 0);
        }
    }

    private static List<String[]> headersAsArray(List<HpackDecoder.HeaderField> fields) {
        List<String[]> out = new ArrayList<>(fields.size());
        for (HpackDecoder.HeaderField f : fields) {
            out.add(new String[]{f.name, f.value});
        }
        return out;
    }

    private static String valOf(List<HpackDecoder.HeaderField> fields, String name) {
        for (HpackDecoder.HeaderField f : fields) {
            if (name.equals(f.name)) return f.value;
        }
        return null;
    }

    private static boolean hasField(List<HpackDecoder.HeaderField> fields, String name) {
        return valOf(fields, name) != null;
    }

    private static int parseStatus(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private static String orEmpty(String s) {
        return s == null ? "" : s;
    }

    static String stripPortKeep(String authority) {
        if (authority.startsWith("[")) {
            int e = authority.indexOf(']');
            return e > 0 ? authority.substring(0, e + 1) : authority;
        }
        int c = authority.lastIndexOf(':');
        return c > 0 ? authority.substring(0, c) : authority;
    }

    private static byte[] append(byte[] body, byte[] src, int off, int len) {
        byte[] joined = new byte[body.length + len];
        System.arraycopy(body, 0, joined, 0, body.length);
        System.arraycopy(src, off, joined, body.length, len);
        return joined;
    }

    /** Non-pseudo headers as text block WITHOUT body and WITHOUT final CRLFCRLF. */
    private static String headText(List<HpackDecoder.HeaderField> fields, String firstLine) {
        StringBuilder sb = new StringBuilder(firstLine.length() + fields.size() * 24 + 8);
        sb.append(firstLine).append("\r\n");
        for (HpackDecoder.HeaderField f : fields) {
            if (f.name.startsWith(":")) continue;
            sb.append(f.name).append(": ").append(f.value).append("\r\n");
        }
        sb.append("\r\n");
        return sb.toString();
    }

    private static byte[] concatHeadBody(String head, byte[] body) {
        byte[] headB = head.getBytes(StandardCharsets.UTF_8);
        byte[] out;
        if (body == null || body.length == 0) {
            out = new byte[headB.length];
            System.arraycopy(headB, 0, out, 0, headB.length);
            return out;
        }
        out = new byte[headB.length + body.length];
        System.arraycopy(headB, 0, out, 0, headB.length);
        System.arraycopy(body, 0, out, headB.length, body.length);
        return out;
    }
}


