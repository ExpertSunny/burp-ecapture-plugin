package com.ecapture.burp.pb;

/**
 * Minimal protobuf wire-format reader. Supports the subset of the wire format used by the
 * eCaptureQ protocol (varint fields, length-delimited fields/strings/bytes/submessages).
 * Written to keep the extension dependency-free: a single jar can be dropped into Burp.
 */
final class PbReader {
    private final byte[] data;
    private final int limit;
    private int pos;
    private int tag = 0;
    private int wireType = 0;

    PbReader(byte[] data) {
        this(data, 0, data.length);
    }

    PbReader(byte[] data, int off, int len) {
        this.data = data;
        this.pos = off;
        this.limit = off + len;
    }

    /**
     * Reads the next field key. Keys are varints, so field numbers >= 16 (e.g. Event.stream_id,
     * Event.sequence) take two bytes whose first byte has the high bit set.
     */
    boolean hasField() {
        while (pos < limit) {
            long t = readVarInt();
            tag = (int) (t >>> 3);
            wireType = (int) (t & 7);
            if (tag == 0) {
                pos = limit; // malformed: stop rather than misread payload bytes as keys
                return false;
            }
            if (wireType == 3 || wireType == 4) { // groups are not used by eCaptureQ
                continue;
            }
            return true;
        }
        return false;
    }

    int field() {
        return tag;
    }

    /** Reads a varint, position depends solely on the wire type. */
    long readVarInt() {
        long r = 0;
        int shift = 0;
        while (pos < limit) {
            byte b = data[pos++];
            r |= ((long) (b & 0x7F)) << shift;
            if (b >= 0) break;
            shift += 7;
            if (shift > 63) break;
        }
        return r;
    }

    /** Skips the value of the field whose key was just read by {@link #hasField()}. */
    void skip() {
        switch (wireType) {
            case 0:
                readVarInt();
                break;
            case 1:
                pos = Math.min(pos + 8, limit);
                break;
            case 2: {
                int len = readLen();
                pos = (len < 0 || len > limit - pos) ? limit : pos + len;
                break;
            }
            case 5:
                pos = Math.min(pos + 4, limit);
                break;
            default:
                pos = limit;
        }
    }

    int readLen() {
        return (int) readVarInt();
    }

    PbReader sub() {
        int len = readLen();
        int end = Math.min(pos + len, limit);
        PbReader r = new PbReader(data, pos, end - pos);
        pos = end;
        return r;
    }

    byte[] bytes() {
        int len = readLen();
        int end = Math.min(pos + len, limit);
        byte[] out = new byte[end - pos];
        System.arraycopy(data, pos, out, 0, out.length);
        pos = end;
        return out;
    }

    String string() {
        return new String(bytes(), java.nio.charset.StandardCharsets.UTF_8);
    }

    boolean bool() {
        return readVarInt() != 0;
    }
}
