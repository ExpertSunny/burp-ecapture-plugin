package com.ecapture.burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.ecapture.burp.h2.HpackDecoder;
import com.ecapture.burp.h2.Http2Decoder;
import com.ecapture.burp.http.Http1Parser;
import com.ecapture.burp.pb.LogEntry;

/**
 * Standalone test harness (no Burp needed):
 *   java -cp build\classes com.ecapture.burp.SelfTest
 */
public final class SelfTest {

    static int passed = 0;
    static int failed = 0;

    public static void main(String[] args) {
        testHpack();            // RFC 7541 Appendix C examples
        testHttp1Parser();
        testHttp2Decoder();     // framing + HPACK through the connection decoder
        testProtobuf();
        testEngineH1();
        testEngineH2();
        testEngineLegacyText();
        System.out.println();
        System.out.println("passed=" + passed + " failed=" + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static void ok(boolean cond, String name) {
        if (cond) {
            passed++;
        } else {
            failed++;
            System.out.println("FAIL: " + name);
        }
    }

    static String join(List<HpackDecoder.HeaderField> fields) {
        StringBuilder sb = new StringBuilder();
        for (HpackDecoder.HeaderField f : fields) {
            sb.append(f.name).append("=").append(f.value).append(";");
        }
        return sb.toString();
    }

    static byte[] hex(String s) {
        s = s.replace(" ", "").replace("\n", "");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    // ---------------------------------------------------------------- HPACK

    static void testHpack() {
        // C.4.1: all Huffman-coded authority "www.example.com" (f1e3...f4ff)
        HpackDecoder d = new HpackDecoder();
        List<HpackDecoder.HeaderField> r = d.decode(
            hex("82 86 84 41 8c f1e3c2e5f23a6ba0ab90f4ff"));
        ok(":method=GET;:scheme=http;:path=/;:authority=www.example.com;".equals(join(r)),
            "C.4.1 huffman: " + join(r));

        // literal value Huffman "no-cache" from C.3.2/C.4.2 (a8eb10649cbf)
        HpackDecoder d2 = new HpackDecoder();
        List<HpackDecoder.HeaderField> rv = d2.decode(hex("58 86 a8eb10649cbf"));
        ok("cache-control=no-cache;".equals(join(rv)),
            "huffman value: " + join(rv));

        // C.3.1 -> C.3.2 -> C.3.3 against one decoder with dynamic table state
        HpackDecoder seq = new HpackDecoder();
        List<HpackDecoder.HeaderField> s1 = seq.decode(
            hex("82 86 84 41 0f 7777772e6578616d706c652e636f6d"));
        ok(":method=GET;:scheme=http;:path=/;:authority=www.example.com;".equals(join(s1)),
            "C.3.1: " + join(s1));
        List<HpackDecoder.HeaderField> s2 = seq.decode(hex("82 86 84 be 58 86 a8eb10649cbf"));
        ok(":method=GET;:scheme=http;:path=/;:authority=www.example.com;cache-control=no-cache;"
            .equals(join(s2)), "C.3.2: " + join(s2));
        List<HpackDecoder.HeaderField> s3 = seq.decode(
            hex("8287 85bf 400a 637573746f6d2d6b6579 0c63 7573746f6d2d76616c7565"));
        ok(":method=GET;:scheme=https;:path=/index.html;:authority=www.example.com;custom-key=custom-value;"
            .equals(join(s3)), "C.3.3: " + join(s3));

        // C.4.1 -> C.4.2 -> C.4.3 (full-huffman sequence against one decoder)
        HpackDecoder dh = new HpackDecoder();
        dh.decode(hex("82 86 84 41 8c f1e3c2e5f23a6ba0ab90f4ff"));       // C.4.1
        dh.decode(hex("82 86 84 be 58 86 a8eb10649cbf"));               // C.4.2
        List<HpackDecoder.HeaderField> c43 = dh.decode(
            hex("8287 85bf 40 88 25a849e95ba97d7f 89 25a849e95bb8e8b4bf")); // C.4.3
        ok(":method=GET;:scheme=https;:path=/index.html;:authority=www.example.com;custom-key=custom-value;"
            .equals(join(c43)), "C.4.3: " + join(c43));
    }

    // ---------------------------------------------------------------- HTTP/1

    static void testHttp1Parser() {
        // request split at an arbitrary offset inside the body, plus CL body
        final List<Http1Parser.Message> reqs = new ArrayList<>();
        Http1Parser p = new Http1Parser(true, new Http1Parser.Callback() {
            @Override public void onMessage(Http1Parser.Message m) { }
            @Override public void onBody(Http1Parser.Message m, byte[] data) { }
            @Override public void onFinal(Http1Parser.Message m) { reqs.add(m); }
        });
        byte[] req = ("POST /api/login HTTP/1.1\r\nHost: api.example.com\r\n"
            + "Content-Length: 11\r\n\r\nhello world").getBytes(StandardCharsets.ISO_8859_1);
        ok(p.feed(req, 0, 30), "req feed 1");
        ok(p.feed(req, 30, req.length - 30), "req feed 2");
        ok(reqs.size() == 1 && "POST".equals(reqs.get(0).method())
            && "/api/login".equals(reqs.get(0).path())
            && "hello world".equals(new String(reqs.get(0).body, StandardCharsets.ISO_8859_1)),
            "req parse: " + (reqs.isEmpty() ? "none" : reqs.get(0).summary()));

        // response whose head terminator CRLF CRLF is split across two feeds
        final List<Http1Parser.Message> heads = new ArrayList<>();
        Http1Parser q2 = new Http1Parser(false, new Http1Parser.Callback() {
            @Override public void onMessage(Http1Parser.Message m) { }
            @Override public void onBody(Http1Parser.Message m, byte[] data) { }
            @Override public void onFinal(Http1Parser.Message m) { heads.add(m); }
        });
        byte[] small = ("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        ok(q2.feed(small, 0, 30), "split-head feed 1");
        ok(q2.feed(small, 30, small.length - 30), "split-head feed 2");
        ok(heads.size() == 1 && heads.get(0).statusCode() == 204, "split head: " + heads.size());

        // chunked response, split boundary inside chunk data
        final List<Http1Parser.Message> resps = new ArrayList<>();
        Http1Parser q = new Http1Parser(false, new Http1Parser.Callback() {
            @Override public void onMessage(Http1Parser.Message m) { }
            @Override public void onBody(Http1Parser.Message m, byte[] data) { }
            @Override public void onFinal(Http1Parser.Message m) { resps.add(m); }
        });
        String respText = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        byte[] resp = respText.getBytes(StandardCharsets.ISO_8859_1);
        int cut = 63;
        ok(q.feed(resp, 0, cut), "resp feed 1");
        ok(q.feed(resp, cut, resp.length - cut), "resp feed 2");
        ok(resps.size() == 1 && resps.get(0).statusCode() == 200
            && "hello world".equals(new String(resps.get(0).body, StandardCharsets.ISO_8859_1)),
            "resp chunked parse: "
                + (resps.isEmpty() ? "none" : resps.get(0).summary()
                    + " body=" + new String(resps.get(0).body, StandardCharsets.ISO_8859_1)));

        // garbage on the request side must fail cleanly
        Http1Parser bad = new Http1Parser(true, new Http1Parser.Callback() {
            @Override public void onMessage(Http1Parser.Message m) { }
            @Override public void onBody(Http1Parser.Message m, byte[] data) { }
            @Override public void onFinal(Http1Parser.Message m) { }
        });
        byte[] garbage = "NOTAMETHOD / HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        ok(!bad.feed(garbage, 0, garbage.length), "garbage fails");
    }

    // ---------------------------------------------------------------- HTTP/2

    static void testHttp2Decoder() {
        final List<String> events = new ArrayList<>();
        Http2Decoder dec = new Http2Decoder(true, new Http2Decoder.Listener() {
            @Override public void onHeaders(long streamId, List<HpackDecoder.HeaderField> fields,
                                            boolean endStream, boolean push) {
                events.add("H:" + streamId + (push ? ":push" : "") + ":" + join(fields) + ":" + endStream);
            }

            @Override public void onData(long streamId, byte[] data, boolean endStream) {
                events.add("D:" + streamId + ":" + new String(data, StandardCharsets.ISO_8859_1) + ":" + endStream);
            }
        });

        byte[] preface = Hex.PREFACE; // 24-byte client preface
        dec.feed(preface, 0, 12);
        dec.feed(preface, 12, 12);

        // empty SETTINGS frame
        byte[] settings = hex("000000" + "04" + "00" + "00000000");
        dec.feed(settings, 0, settings.length);

        // HEADERS on stream 1 with END_HEADERS: block = C.4.1 (82 86 84 41 8c huff...)
        byte[] block = hex("82 86 84 41 8c f1e3c2e5f23a6ba0ab90f4ff");
        byte[] frame = frame(Http2Decoder.HEADERS, 0x04, 1, block);
        dec.feed(frame, 0, frame.length);

        // DATA with padding on stream 1: pad=1 -> body "ping"
        byte[] payload = new byte[6];
        payload[0] = 1; // pad length
        byte[] body = "ping".getBytes(StandardCharsets.ISO_8859_1);
        System.arraycopy(body, 0, payload, 1, body.length);
        byte[] dframe = frame(Http2Decoder.DATA, 0x08 | 0x01, 1, payload);
        dec.feed(dframe, 0, dframe.length);

        String joined = String.join("|", events);
        boolean h = events.stream().anyMatch(e -> e.startsWith("H:1:")
            && e.contains(":method=GET") && e.contains(":authority=www.example.com")
            && e.endsWith(":false"));
        boolean d = events.stream().anyMatch(e -> e.endsWith("D:1:ping:true")
            || e.contains("D:1:ping:true"));
        ok(h, "h2 headers decoded");
        ok(d, "h2 data (padded) decoded");
        ok(!dec.failed(), "h2 decoder did not fail");
        if (!h || !d) {
            System.out.println("  h2 trace: " + joined);
        }

        // non-matching preface must flip the decoder to failed
        Http2Decoder bad = new Http2Decoder(true, new Http2Decoder.Listener() {
            @Override public void onHeaders(long s, List<HpackDecoder.HeaderField> f, boolean e, boolean p) { }
            @Override public void onData(long s, byte[] data, boolean e) { }
        });
        bad.feed("GET / HTTP/1.1\r\n".getBytes(StandardCharsets.ISO_8859_1), 0, 15);
        ok(bad.failed(), "h2 fails on non-preface");
    }

    static byte[] frame(int type, int flags, long stream, byte[] payload) {
        byte[] f = new byte[9 + payload.length];
        f[0] = (byte) ((payload.length >> 16) & 0xFF);
        f[1] = (byte) ((payload.length >> 8) & 0xFF);
        f[2] = (byte) (payload.length & 0xFF);
        f[3] = (byte) type;
        f[4] = (byte) flags;
        f[5] = (byte) ((stream >> 24) & 0x7F);
        f[6] = (byte) ((stream >> 16) & 0xFF);
        f[7] = (byte) ((stream >> 8) & 0xFF);
        f[8] = (byte) (stream & 0xFF);
        System.arraycopy(payload, 0, f, 9, payload.length);
        return f;
    }

    // ---------------------------------------------------------------- protobuf

    static void testProtobuf() {
        // process log: 08 01 22 05 "hello"
        byte[] wire = new byte[9];
        wire[0] = 0x08; wire[1] = 0x01;
        wire[2] = 0x22; wire[3] = 0x05;
        byte[] hello = "hello".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(hello, 0, wire, 4, 5);
        LogEntry le = LogEntry.decode(wire);
        ok(le.logType == LogEntry.PROCESS_LOG && "hello".equals(le.runLogText()), "pb process log");

        // heartbeat: logType=0, payload {ts=123, count=7, message="hb"}
        List<Byte> b = new ArrayList<>();
        b.add((byte) 0x08); b.add((byte) 0x00);
        b.add((byte) 0x1a); b.add((byte) 0x08);
        b.add((byte) 0x08); b.add((byte) 0x7b); // ts 123
        b.add((byte) 0x10); b.add((byte) 0x07); // count 7
        b.add((byte) 0x1a); b.add((byte) 0x02); b.add((byte) 'h'); b.add((byte) 'b');
        byte[] hb = new byte[b.size()];
        for (int i = 0; i < hb.length; i++) hb[i] = b.get(i);
        LogEntry lhb = LogEntry.decode(hb);
        ok(lhb.heartbeat != null && lhb.heartbeat.count == 7 && "hb".equals(lhb.heartbeat.message),
            "pb heartbeat");

        // event: uuid/type/payload/direction
        List<Byte> ev = new ArrayList<>();
        ev.add((byte) 0x08); ev.add((byte) 0x02);          // logtype EVENT
        ev.add((byte) 0x12); ev.add((byte) 0x11);          // field 2 (event), len 17
        byte[] u = "u1".getBytes(StandardCharsets.UTF_8);
        ev.add((byte) 0x12); ev.add((byte) u.length); for (byte x : u) ev.add(x); // uuid
        ev.add((byte) 0x48); ev.add((byte) 9);             // field 9 type=9
        byte[] pl = "abc".getBytes(StandardCharsets.UTF_8);
        ev.add((byte) 0x5a); ev.add((byte) pl.length); for (byte x : pl) ev.add(x); // payload
        byte[] dv = "read".getBytes(StandardCharsets.UTF_8);
        ev.add((byte) 0x72); ev.add((byte) dv.length); for (byte x : dv) ev.add(x); // direction
        byte[] evt = new byte[ev.size()];
        for (int i = 0; i < evt.length; i++) evt[i] = ev.get(i);
        LogEntry l2 = LogEntry.decode(evt);
        ok(l2.logType == LogEntry.EVENT && l2.event != null
            && "u1".equals(l2.event.uuid) && l2.event.type == 9
            && "abc".equals(new String(l2.event.payload, StandardCharsets.UTF_8))
            && "read".equals(l2.event.direction), "pb event");

        // event as eCapture emits it: capture_format=TEXT then sequence=96 (field 17, two-byte
        // key 0x88 0x01) and an unknown length-delimited field 99 (key 0x9a 0x06)
        byte[] inner = {
            0x5a, 0x03, 'G', 'E', 'T',                      // payload
            0x60, 0x01,                                     // capture_format TEXT
            0x72, 0x05, 'w', 'r', 'i', 't', 'e',            // direction
            (byte) 0x9a, 0x06, 0x02, 0x60, 0x00,            // unknown field 99, len 2
            (byte) 0x88, 0x01, 0x60                         // sequence 96
        };
        byte[] full = new byte[4 + inner.length];
        full[0] = 0x08; full[1] = 0x02; full[2] = 0x12; full[3] = (byte) inner.length;
        System.arraycopy(inner, 0, full, 4, inner.length);
        LogEntry l3 = LogEntry.decode(full);
        ok(l3.event != null && l3.event.captureFormat == 1 && l3.event.sequence == 96
            && "GET".equals(new String(l3.event.payload, StandardCharsets.UTF_8))
            && "write".equals(l3.event.direction), "pb event with multi-byte keys");

        // heartbeat as proto3 sends it: log_type=0 is omitted from the wire
        byte[] hb0 = {0x1a, 0x02, 0x10, 0x05};
        LogEntry l4 = LogEntry.decode(hb0);
        ok(l4.logType == LogEntry.HEARTBEAT && l4.heartbeat != null && l4.heartbeat.count == 5,
            "pb heartbeat without log_type");
    }

    // ---------------------------------------------------------------- engine

    static void testEngineH1() {
        final List<CaptureItem> items = new ArrayList<>();
        final List<CaptureItem> updates = new ArrayList<>();
        AssembleEngine eng = new AssembleEngine(new AssembleEngine.Listener() {
            @Override public void onNewItem(CaptureItem item) { items.add(item); }
            @Override public void onUpdatedItem(CaptureItem item) { updates.add(item); }
        });

        eng.onEvent(ev("write", ("GET /a HTTP/1.1\r\nHost: h.com\r\nContent-Length: 5\r\n\r\nhello")
            .getBytes(StandardCharsets.ISO_8859_1)));
        ok(items.size() == 1 && "GET".equals(items.get(0).method) && "h.com".equals(items.get(0).host),
            "engine h1 request row");

        eng.onEvent(ev("read", ("HTTP/1.1 200 OK\r\nServer: t\r\nContent-Length: 2\r\n\r\nhi")
            .getBytes(StandardCharsets.ISO_8859_1)));
        ok(items.size() == 1 && updates.size() == 1
            && updates.get(0).status == 200 && "hi".equals(new String(
                updates.get(0).rawResponse, StandardCharsets.ISO_8859_1)
                .substring(updates.get(0).rawResponse.length - 2)),
            "engine h1 response paired");
    }

    static void testEngineH2() {
        final List<CaptureItem> items = new ArrayList<>();
        final List<CaptureItem> updates = new ArrayList<>();
        AssembleEngine eng = new AssembleEngine(new AssembleEngine.Listener() {
            @Override public void onNewItem(CaptureItem item) { items.add(item); }
            @Override public void onUpdatedItem(CaptureItem item) { updates.add(item); }
        });

        // client half: preface + SETTINGS + HEADERS + DATA(END_STREAM)
        byte[] preface = Hex.PREFACE;
        eng.onEvent(ev("write", preface));
        eng.onEvent(ev("write", hex("000000" + "04" + "00" + "00000000")));
        byte[] block = hex("82" + "87" + "04" + "02" + "2f78");      // :method GET, :scheme https, :path /x
        byte[] block2 = hex("41" + "0b 6578616d706c652e636f6d");     // :authority example.com
        byte[] full = new byte[block.length + block2.length];
        System.arraycopy(block, 0, full, 0, block.length);
        System.arraycopy(block2, 0, full, block.length, block2.length);
        eng.onEvent(ev("write", frame(Http2Decoder.HEADERS, 0x04, 1, full)));
        byte[] body = "hello".getBytes(StandardCharsets.ISO_8859_1);
        eng.onEvent(ev("write", frame(Http2Decoder.DATA, 0x01, 1, body)));

        ok(items.size() == 1, "engine h2 request row exists");
        if (!items.isEmpty()) {
            CaptureItem it = items.get(0);
            ok("GET".equals(it.method) && "/x".equals(it.path) && "example.com".equals(it.host),
                "engine h2 request fields: " + it.method + " " + it.path + " " + it.host);
            String raw = new String(it.rawRequest, StandardCharsets.ISO_8859_1);
            ok(raw.startsWith("GET /x HTTP/2\r\n") && raw.endsWith("hello"), "engine h2 raw render");
        }

        // server half: SETTINGS + HEADERS(:status 200) + DATA(END_STREAM)
        eng.onEvent(evRead("read", hex("000000" + "04" + "00" + "00000000")));
        eng.onEvent(evRead("read", frame(Http2Decoder.HEADERS, 0x04, 1, hex("88"))));
        byte[] resp = "world".getBytes(StandardCharsets.ISO_8859_1);
        eng.onEvent(evRead("read", frame(Http2Decoder.DATA, 0x01, 1, resp)));

        ok(updates.size() >= 1 && items.get(0).status == 200
            && items.get(0).rawResponse != null
            && new String(items.get(0).rawResponse, StandardCharsets.ISO_8859_1)
                .contains("HTTP/2 200"),
            "engine h2 response attached");
    }

    static LogEntry.EventBus ev(String direction, byte[] payload) {
        LogEntry.EventBus e = new LogEntry.EventBus();
        e.captureFormat = 1;
        e.direction = direction;
        e.pid = 1234;
        e.pname = "com.app";
        if ("write".equals(direction)) {
            e.srcIp = "10.0.0.2"; e.srcPort = 5000;
            e.dstIp = "93.0.0.1"; e.dstPort = 443;
        } else {
            e.srcIp = "93.0.0.1"; e.srcPort = 443;
            e.dstIp = "10.0.0.2"; e.dstPort = 5000;
        }
        e.payload = payload;
        return e;
    }

    /** ecapture v2.7.0: Event carries only the text handler's rendering in payload. */
    static void testEngineLegacyText() {
        final List<CaptureItem> items = new ArrayList<>();
        final List<CaptureItem> updates = new ArrayList<>();
        AssembleEngine eng = new AssembleEngine(new AssembleEngine.Listener() {
            @Override public void onNewItem(CaptureItem item) { items.add(item); }
            @Override public void onUpdatedItem(CaptureItem item) { updates.add(item); }
        });
        eng.onEvent(legacy("PID:5539, Comm:npci.org.in/..., TID:6047, FD:1, Tuple: [::]:0->[::]:0\n"));
        eng.onEvent(legacy("PID:5539, Comm:npci.org.in/..., TID:6047, FD:7, "
            + "Tuple: 10.0.0.2:40000->1.2.3.4:443\n"));
        String req = "POST /v1/e HTTP/1.1\r\nHost: bhim.example\r\nContent-Length: 3\r\n\r\nabc";
        eng.onEvent(legacy("[2026-10-19 15:48:00.285] PID:5539 TID:6047 Comm:npci.org.in/... FD:7 WRITE ("
            + req.length() + " bytes):\n" + req + "\n"));
        ok(items.size() == 1 && "POST".equals(items.get(0).method)
            && "bhim.example".equals(items.get(0).host)
            && "1.2.3.4:443".equals(items.get(0).serverAddr)
            && new String(items.get(0).rawRequest, StandardCharsets.ISO_8859_1).endsWith("\r\n\r\nabc"),
            "legacy text request row");
        String resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        eng.onEvent(legacy("[2026-10-19 15:48:00.400] PID:5539 TID:6050 Comm:npci.org.in/... FD:7 READ ("
            + resp.length() + " bytes):\n" + resp + "\n"));
        ok(items.size() == 1 && updates.size() == 1 && updates.get(0).status == 200,
            "legacy text response paired");
        eng.onEvent(legacy("[2026-10-19 15:48:01.000] PID:1 TID:1 Comm:x FD:3 WRITE (2 bytes, hex):\n"
            + "0000 41 41\n"));
        ok(items.size() == 1, "legacy hex output ignored");

        // OkHttp h2: one connection (fd 9) written from three differently named threads
        byte[] block = hex("82" + "87" + "04" + "02" + "2f78" + "41" + "0b 6578616d706c652e636f6d");
        eng.onEvent(legacyBin("OkHttp https:/", 9, "WRITE", Hex.PREFACE));
        eng.onEvent(legacyBin("yAndAckSettings", 9, "WRITE", hex("000000" + "04" + "00" + "00000000")));
        eng.onEvent(legacyBin("jfinserv.in/...", 9, "WRITE", frame(Http2Decoder.HEADERS, 0x05, 1, block)));
        ok(items.size() == 2 && "HTTP/2".equals(items.get(1).kind) && "/x".equals(items.get(1).path)
            && "fd 9".equals(items.get(1).serverAddr), "legacy h2 across threads");

        // a connection that fell back to RAW recovers on the next request line
        eng.onEvent(legacyBin("t", 11, "WRITE", "garbage".getBytes(StandardCharsets.ISO_8859_1)));
        eng.onEvent(legacyBin("t", 11, "WRITE",
            "GET /y HTTP/1.1\r\nHost: h\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)));
        ok(items.size() == 4 && "RAW".equals(items.get(2).kind) && "/y".equals(items.get(3).path),
            "legacy raw connection resyncs");
    }

    static LogEntry.EventBus legacyBin(String comm, int fd, String dir, byte[] data) {
        byte[] head = ("[2026-10-19 22:05:03.043] PID:14776 TID:1 Comm:" + comm + " FD:" + fd + " "
            + dir + " (" + data.length + " bytes):\n").getBytes(StandardCharsets.UTF_8);
        LogEntry.EventBus e = new LogEntry.EventBus();
        e.payload = new byte[head.length + data.length + 1];
        System.arraycopy(head, 0, e.payload, 0, head.length);
        System.arraycopy(data, 0, e.payload, head.length, data.length);
        e.payload[e.payload.length - 1] = '\n';
        return e;
    }

    static LogEntry.EventBus legacy(String text) {
        LogEntry.EventBus e = new LogEntry.EventBus();
        e.payload = text.getBytes(StandardCharsets.UTF_8);
        e.length = e.payload.length;
        return e;
    }

    static LogEntry.EventBus evRead(String direction, byte[] payload) {
        return ev(direction, payload);
    }

    // ---------------------------------------------------------------- misc

    /** Hex constants. */
    static final class Hex {
        static final byte[] PREFACE = {
            'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n',
            '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'
        };
    }
}
