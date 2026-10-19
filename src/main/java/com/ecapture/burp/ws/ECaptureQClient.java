package com.ecapture.burp.ws;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;

import com.ecapture.burp.pb.LogEntry;

/**
 * WebSocket client for eCaptureQ (ecapture --ecaptureq=ws://...).
 * Each binary frame from the server contains one protobuf LogEntry.
 */
public final class ECaptureQClient implements WebSocket.Listener {

    public interface Handler {
        void onProcessLog(String line);

        void onHeartbeat(long ts, long count, String message);

        /** Captured plaintext chunk; pass it to the assembler. */
        void onEvent(LogEntry.EventBus event);

        void onState(boolean connected, String detail);
    }

    private final URI uri;
    private final Handler handler;
    private final HttpClient http = HttpClient.newHttpClient();
    private final AtomicBoolean closing = new AtomicBoolean(false);
    private volatile WebSocket ws;
    private final ByteArrayOutputStream partial = new ByteArrayOutputStream();

    public ECaptureQClient(String host, int port, Handler handler) {
        this.uri = URI.create("ws://" + host + ":" + port + "/");
        this.handler = handler;
    }

    public void connect() {
        closing.set(false);
        try {
            http.newWebSocketBuilder()
                // eCapture's server (golang.org/x/net/websocket.Handler) rejects any
                // handshake whose Origin header is missing/null with HTTP 403.
                .header("Origin", "http://localhost/")
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .buildAsync(uri, this)
                .whenComplete((w, ex) -> {
                    if (ex != null) {
                        handler.onState(false, "connect failed: " + rootMessage(ex));
                    }
                    // onOpen fires first when the handshake succeeds
                });
        } catch (Exception ex) {
            handler.onState(false, "connect failed: " + ex);
        }
    }

    public void disconnect() {
        closing.set(true);
        WebSocket w = ws;
        if (w != null) {
            try {
                w.sendClose(WebSocket.NORMAL_CLOSURE, "bye");
            } catch (Exception ignored) {
            }
        }
        handler.onState(false, "disconnected by user");
    }

    private Throwable rootCause(Throwable t) {
        while (t.getCause() != null) t = t.getCause();
        return t;
    }

    private String rootMessage(Throwable t) {
        Throwable c = rootCause(t);
        return c == null ? t.toString() : c.toString();
    }

    @Override public void onOpen(WebSocket w) {
        ws = w;
        partial.reset();
        handler.onState(true, "connected");
        // mobile: no need for us to pong; server only sends
        w.request(1);
    }

    @Override public CompletionStage<?> onBinary(WebSocket w, ByteBuffer data, boolean last) {
        byte[] bytes = new byte[data.remaining()];
        data.get(bytes);
        ByteArrayOutputStream buf = partial;
        if (!last) {
            synchronized (buf) {
                buf.write(bytes, 0, bytes.length);
            }
            w.request(1);
            return null;
        }
        byte[] whole;
        synchronized (buf) {
            buf.write(bytes, 0, bytes.length);
            whole = buf.toByteArray();
            buf.reset();
        }
        deliver(whole);
        w.request(1);
        return null;
    }

    private void deliver(byte[] wire) {
        try {
            LogEntry entry = LogEntry.decode(wire);
            switch (entry.logType) {
                case LogEntry.PROCESS_LOG:
                    handler.onProcessLog(entry.runLogText());
                    break;
                case LogEntry.HEARTBEAT:
                    if (entry.heartbeat != null) {
                        handler.onHeartbeat(entry.heartbeat.timestamp, entry.heartbeat.count, entry.heartbeat.message);
                    }
                    break;
                case LogEntry.EVENT:
                    if (entry.event != null) {
                        handler.onEvent(entry.event);
                    }
                    break;
                default:
                    break;
            }
        } catch (Throwable t) {
            handler.onProcessLog("[plugin] failed to decode a LogEntry: " + t);
        }
    }

    @Override public CompletionStage<?> onClose(WebSocket w, int statusCode, String reason) {
        ws = w;
        handler.onState(false, "closed: " + statusCode + (reason == null || reason.isEmpty() ? "" : " (" + reason + ")"));
        return null;
    }

    @Override public void onError(WebSocket w, Throwable error) {
        if (closing.get()) return;
        handler.onState(false, "error: " + rootMessage(error));
    }

    @Override public CompletionStage<?> onPing(WebSocket w, ByteBuffer message) {
        w.request(1);
        // the JDK WebSocket implementation does NOT auto-pong, so reply manually
        w.sendPong(message.hasRemaining() ? message : ByteBuffer.allocate(0));
        return null;
    }

    @Override public CompletionStage<?> onPong(WebSocket w, ByteBuffer message) {
        w.request(1);
        return null;
    }
}
