package com.ecapture.burp.h2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Incremental HTTP/2 connection decoder for one half (one direction) of a TLS connection.
 *
 * <p>Sits on top of the plaintext SSL_read/SSL_write stream that eCapture exposes in text
 * mode. When the request side is fed, the 24-byte client connection preface is consumed and
 * verified first. Each direction owns an independent HPACK dynamic table (RFC 7540 §4.2).
 * A HEADERS block may span CONTINUATION frames; no other frame may intervene in between
 * (HTTP/2 forbids it) and that condition is enforced.
 *
 * <p>On any protocol error, {@link #failed()} flips to true and further feeds are no-ops.
 * The caller should then switch the connection to raw mode.
 */
public final class Http2Decoder {

    public static final int DATA = 0, HEADERS = 1, PRIORITY = 2, RST_STREAM = 3,
        SETTINGS = 4, PUSH_PROMISE = 5, PING = 6, GOAWAY = 7, WINDOW_UPDATE = 8, CONTINUATION = 9;

    public static final byte[] CLIENT_PREFACE =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    public interface Listener {
        /** Decoded header list of a stream (also trailers for later calls of same stream). */
        void onHeaders(long streamId, List<HpackDecoder.HeaderField> fields, boolean endStream, boolean push);

        /** DATA frame payload chunk (body bytes only, padding stripped). */
        void onData(long streamId, byte[] data, boolean endStream);
    }

    private static final int MAX_HEADER_DATA = 1 << 20;
    private static final int MAX_FRAME = 1 << 24;

    private static final int ST_PREFACE = 0;
    private static final int ST_HEADER = 1;
    private static final int ST_PAYLOAD = 2;
    private static final int ST_FAILED = 3;

    private final boolean requestDirection;
    private final Listener listener;
    private final HpackDecoder hpack = new HpackDecoder();

    private int stage;

    private byte[] buf;
    private int pos;
    private int end;

    private int headerFill = 0;
    private final byte[] headerBytes = new byte[9];
    private final byte[] prefaceBytes = new byte[CLIENT_PREFACE.length];

    private int frameType, frameFlags;
    private long frameLength, frameStream;
    private int payloadFill = 0;
    private byte[] payloadBuf = null;

    private boolean inHeaderBlock = false; // HEADERS seen without END_HEADERS
    private ByteArrayOutputStream contData = new ByteArrayOutputStream();
    private long contStream = -1;
    private boolean contEndStream = false;

    public Http2Decoder(boolean requestDirection, Listener listener) {
        this.requestDirection = requestDirection;
        this.listener = listener;
        this.stage = requestDirection ? ST_PREFACE : ST_HEADER;
    }

    public boolean failed() {
        return stage == ST_FAILED;
    }

    /**
     * Accepts more bytes of the raw plaintext stream of one side of the connection.
     * May be called with subsequent read/write chunks in order.
     */
    public synchronized void feed(byte[] chunk, int off, int len) {
        if (stage == ST_FAILED) return;
        this.buf = chunk;
        this.pos = off;
        this.end = off + len;
        try {
            pump();
        } catch (Throwable t) {
            fail();
        }
    }

    private void fail() {
        stage = ST_FAILED;
        buf = null;
        payloadBuf = null;
        contData = new ByteArrayOutputStream();
    }

    private int remaining() {
        return end - pos;
    }

    private void pump() throws IOException {
        while (true) {
            if (stage == ST_HEADER) {
                int need = 9 - headerFill;
                int have = remaining();
                int take = Math.min(need, have);
                System.arraycopy(buf, pos, headerBytes, headerFill, take);
                headerFill += take;
                pos += take;
                if (headerFill < 9) return;
                frameLength = ((headerBytes[0] & 0xFFL) << 16) | ((headerBytes[1] & 0xFFL) << 8) | (headerBytes[2] & 0xFFL);
                frameType = headerBytes[3] & 0xFF;
                frameFlags = headerBytes[4] & 0xFF;
                frameStream = ((headerBytes[5] & 0x7FL) << 24)
                    | ((headerBytes[6] & 0xFFL) << 16)
                    | ((headerBytes[7] & 0xFFL) << 8)
                    | (headerBytes[8] & 0xFFL);
                if (frameLength > MAX_FRAME) {
                    throw new IOException("frame too long: " + frameLength);
                }
                if (frameLength == 0) {
                    stage = ST_HEADER;
                    headerFill = 0;
                    dispatch(new byte[0], 0, 0);
                } else {
                    payloadBuf = new byte[(int) frameLength];
                    payloadFill = 0;
                    stage = ST_PAYLOAD;
                }
            } else if (stage == ST_PAYLOAD) {
                int need = (int) frameLength - payloadFill;
                int have = remaining();
                if (have <= 0) return;
                int take = Math.min(need, have);
                System.arraycopy(buf, pos, payloadBuf, payloadFill, take);
                payloadFill += take;
                pos += take;
                if (payloadFill < (int) frameLength) return;
                byte[] payload = payloadBuf;
                payloadBuf = null;
                headerFill = 0;
                stage = ST_HEADER;
                dispatch(payload, 0, payload.length);
            } else if (stage == ST_PREFACE) {
                int need = CLIENT_PREFACE.length - headerFill;
                int have = remaining();
                int take = Math.min(need, have);
                System.arraycopy(buf, pos, prefaceBytes, headerFill, take);
                headerFill += take;
                pos += take;
                if (headerFill < CLIENT_PREFACE.length) {
                    // verify what we have so far against the expected prefix
                    for (int i = 0; i < headerFill; i++) {
                        if (prefaceBytes[i] != CLIENT_PREFACE[i]) {
                            throw new IOException("not an HTTP/2 connection preface");
                        }
                    }
                    return;
                }
                for (int i = 0; i < CLIENT_PREFACE.length; i++) {
                    if (prefaceBytes[i] != CLIENT_PREFACE[i]) {
                        throw new IOException("not an HTTP/2 connection preface");
                    }
                }
                headerFill = 0;
                stage = ST_HEADER;
            } else {
                return; // ST_FAILED etc.
            }
        }
    }

    /** Splits a complete frame payload and applies its semantics. */
    private void dispatch(byte[] payload, int off, int len) throws IOException {
        if (inHeaderBlock) {
            if (frameType != CONTINUATION) {
                throw new IOException("frame " + frameType + " interleaved inside header block");
            }
            if (len > 0) {
                contData.write(payload, off, len);
            }
            if ((frameFlags & 0x4) != 0) { // END_HEADERS
                byte[] block = contData.toByteArray();
                contData = new ByteArrayOutputStream();
                long stream = contStream;
                boolean es = contEndStream;
                inHeaderBlock = false;
                deliverHeaders(stream, block, 0, block.length, es, false);
            }
            return;
        }

        int flags = frameFlags;
        switch (frameType) {
            case DATA: {
                boolean endStream = (flags & 0x1) != 0;
                int p = 0, pad = 0;
                if ((flags & 0x8) != 0) {
                    pad = payload[off] & 0xFF;
                    p = 1;
                }
                int bodyEnd = off + len - pad;
                if (bodyEnd < off + p) throw new IOException("bad DATA padding");
                int n = bodyEnd - (off + p);
                byte[] data = n > 0 ? new byte[n] : new byte[0];
                if (n > 0) System.arraycopy(payload, off + p, data, 0, n);
                listener.onData(frameStream, data, endStream);
                break;
            }
            case HEADERS:
            case PUSH_PROMISE: {
                boolean push = frameType == PUSH_PROMISE;
                long stream = push
                    ? ((payload[off] & 0x7FL) << 24) | ((payload[off + 1] & 0xFFL) << 16)
                        | ((payload[off + 2] & 0xFFL) << 8) | (payload[off + 3] & 0xFFL)
                    : frameStream;
                int p = push ? 4 : 0;
                int pad = 0;
                if ((flags & 0x8) != 0) { // PADDED
                    pad = payload[off + p] & 0xFF;
                    p += 1;
                }
                if (!push && (flags & 0x20) != 0) { // PRIORITY (client HEADERS only)
                    p += 5;
                }
                if (p + pad > len) throw new IOException("bad HEADERS padding");
                int hoff = off + p;
                int hlen = len - p - pad;
                boolean endHeaders = (flags & 0x4) != 0;
                boolean endStream = (flags & 0x1) != 0;
                if (endHeaders) {
                    deliverHeaders(stream, payload, hoff, hlen, endStream, push);
                } else {
                    contData.reset();
                    contData.write(payload, hoff, hlen);
                    contStream = stream;
                    contEndStream = endStream;
                    inHeaderBlock = true;
                }
                break;
            }
            case CONTINUATION:
                throw new IOException("CONTINUATION outside header block");
            case SETTINGS:
            case PRIORITY:
            case RST_STREAM:
            case PING:
            case WINDOW_UPDATE:
            case GOAWAY:
                break; // nothing to do for extraction purposes
            default:
                break; // unknown frame: skip
        }
    }

    private void deliverHeaders(long stream, byte[] block, int off, int len, boolean endStream, boolean push) throws IOException {
        List<HpackDecoder.HeaderField> fields;
        try {
            fields = hpack.decode(block, off, len);
        } catch (RuntimeException e) {
            throw new IOException("hpack decode failed: " + e.getMessage());
        }
        listener.onHeaders(stream, fields, endStream, push);
    }
}
