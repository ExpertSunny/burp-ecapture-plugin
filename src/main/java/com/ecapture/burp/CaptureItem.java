package com.ecapture.burp;

import java.util.List;

/**
 * One row in the capture table. An item is either an HTTP exchange (request and,
 * when seen, response) or a raw captured chunk that could not be parsed.
 */
public final class CaptureItem {
    public final int id;
    public final long ts;
    public final String connKey;

    public final long pid;
    public final String pname;
    public final String clientAddr; // client side ip:port
    public final String serverAddr; // server side ip:port

    public String kind; // HTTP/1 | HTTP/2 | PUSH | RAW
    public String method = "";
    public String host = "";     // service authority best known (Host/:authority or server addr)
    public String path = "";
    public String summary = "";
    public String contentType = "";
    public int status = -1;

    public volatile byte[] rawRequest;    // rendered request bytes (h1 wire format style)
    public volatile byte[] rawResponse;   // rendered response bytes
    public volatile boolean requestComplete = true;
    public volatile boolean responseComplete = false;
    public boolean truncated = false;

    /** structured HTTP/2 headers for exact re-issuing (null for HTTP/1 / RAW rows). */
    public volatile List<String[]> h2reqHeaders;
    public volatile byte[] h2reqBody = new byte[0];
    public volatile List<String[]> h2respHeaders;
    public volatile byte[] h2respBody = new byte[0];

    public long h2StreamId = -1;

    public CaptureItem(int id, long ts, String connKey, long pid, String pname,
                       String clientAddr, String serverAddr, String kind) {
        this.id = id;
        this.ts = ts;
        this.connKey = connKey;
        this.pid = pid;
        this.pname = pname;
        this.clientAddr = clientAddr;
        this.serverAddr = serverAddr;
        this.kind = kind;
    }

    public boolean hasResponse() {
        return rawResponse != null && rawResponse.length > 0;
    }

    public boolean hasRequest() {
        return rawRequest != null && rawRequest.length > 0;
    }

    public int requestLen() {
        return rawRequest == null ? 0 : rawRequest.length;
    }

    public int responseLen() {
        return rawResponse == null ? 0 : rawResponse.length;
    }

    /** first line of the response, extracted for display when a status exists */
    public String responseStatusText() {
        byte[] r = rawResponse;
        if (r == null) return "";
        int n = Math.min(r.length, 512);
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            char c = (char) (r[i] & 0xFF);
            if (c == '\r' || c == '\n') {
                return sb.toString();
            }
            sb.append(c);
        }
        return sb.toString();
    }

    public static String formatK(int n) {
        if (n < 1024) return String.valueOf(n);
        if (n < 1024 * 1024) return String.format("%.1fK", n / 1024.0);
        return String.format("%.1fM", n / 1048576.0);
    }
}
