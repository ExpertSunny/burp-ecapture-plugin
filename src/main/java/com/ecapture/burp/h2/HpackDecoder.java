package com.ecapture.burp.h2;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HPACK (RFC 7541) header block decoder with dynamic table state. The dynamic
 * table max size follows the HTTP/2 SETTINGS_HEADER_TABLE_SIZE signalled by the
 * peer (via dynamic table size updates in the header block).
 *
 * All integer reading is done bit-wise so the decoder works at any bit alignment.
 */
public final class HpackDecoder {

    public static final class HeaderField {
        public final String name;
        public final String value;

        public HeaderField(String name, String value) {
            this.name = name;
            this.value = value;
        }

        @Override public String toString() {
            return name + ": " + value;
        }
    }

    /** Huffman symbol lookup keyed by (length << 32 | code). */
    private static final Map<Long, Integer> HUFF = new HashMap<>();
    /** canonical range guards per code length: [len-5] -> {minCode, maxCode} */
    private static final int[] CODE_MIN = new int[26];
    private static final int[] CODE_MAX = new int[26];
    static {
        java.util.Arrays.fill(CODE_MIN, Integer.MAX_VALUE);
        java.util.Arrays.fill(CODE_MAX, -1);
        for (int sym = 0; sym <= 256; sym++) {
            int[] entry = HpackTables.HUFFMAN_CODES[sym];
            HUFF.put(((long) entry[1] << 32) | entry[0], sym);
            int idx = entry[1] - 5;
            if (idx < 0) throw new IllegalStateException("huffman code shorter than 5 bits");
            CODE_MIN[idx] = Math.min(CODE_MIN[idx], entry[0]);
            CODE_MAX[idx] = Math.max(CODE_MAX[idx], entry[0]);
        }
    }

    private static long entrySize(String name, String value) {
        return name.length() + value.length() + 32;
    }

    /** newest first, matching RFC 7541 section 2.3.2 index semantics. */
    private final List<HeaderField> dynamic = new ArrayList<>();
    private long dynamicSize = 0;
    private long currentTableMaxSize = 4096;

    public synchronized void updateTableMaxSize(long size) {
        this.currentTableMaxSize = size;
        evict();
    }

    public synchronized long dynamicTableSize() {
        return dynamicSize;
    }

    private void addDynamic(HeaderField hf) {
        if (currentTableMaxSize <= 0) {
            return; // do not insert
        }
        dynamic.add(0, hf);
        dynamicSize += entrySize(hf.name, hf.value);
        evict();
        if (dynamicSize > (16L << 20)) { // decoder safety limit
            dynamic.clear();
            dynamicSize = 0;
        }
    }

    private void evict() {
        while (dynamicSize > currentTableMaxSize && !dynamic.isEmpty()) {
            HeaderField last = dynamic.remove(dynamic.size() - 1);
            dynamicSize -= entrySize(last.name, last.value);
        }
    }

    private HeaderField lookup(long index) {
        if (index <= HpackTables.STATIC_TABLE.length) {
            String[] e = HpackTables.STATIC_TABLE[(int) index - 1];
            return new HeaderField(e[0], e[1]);
        }
        int dynIdx = (int) (index - HpackTables.STATIC_TABLE.length - 1);
        if (dynIdx < 0 || dynIdx >= dynamic.size()) {
            throw new IllegalArgumentException("invalid HPACK index " + index);
        }
        return dynamic.get(dynIdx);
    }

    /** Decodes a complete header block. Buffer must contain exactly the block. */
    public synchronized List<HeaderField> decode(byte[] block) {
        return decode(block, 0, block.length);
    }

    /**
     * Header blocks are byte-aligned: each opcode (flag bits plus its integer prefix)
     * fills whole octets and string literals self-pad to an octet boundary, so all
     * integers are read from whole bytes. Any leftover of a final Huffman string lives
     * inside the string itself as EOS padding and never reaches the opcode loop.
     */
    public synchronized List<HeaderField> decode(byte[] buf, int off, int len) {
        List<HeaderField> out = new ArrayList<>();
        Cursor c = new Cursor(buf, off, off + len);
        while (!c.done()) {
            int first = c.read();
            if ((first & 0x80) != 0) { // 6.1 indexed header field
                long idx = readInt(c, first & 0x7f, 7);
                if (idx == 0) throw new IllegalArgumentException("HPACK index 0");
                out.add(lookup(idx));
            } else if ((first & 0xC0) == 0x40) { // 6.2.1 literal, incremental indexing
                literal(c, out, first & 0x3f, 6, true);
            } else if ((first & 0xE0) == 0x20) { // 6.3 dynamic table size update
                long newSize = readInt(c, first & 0x1f, 5);
                currentTableMaxSize = newSize;
                evict();
            } else { // 6.2.2/6.2.3 literal without / never indexed
                literal(c, out, first & 0x0f, 4, false);
            }
        }
        return out;
    }

    private void literal(Cursor c, List<HeaderField> out, int namePrefix, int prefixLen, boolean insert) {
        long nameIdx = readInt(c, namePrefix, prefixLen);
        String name = nameIdx == 0 ? readString(c) : lookup(nameIdx).name;
        String value = readString(c);
        HeaderField hf = new HeaderField(name, value);
        out.add(hf);
        if (insert) {
            addDynamic(hf);
        }
    }

    private static String readString(Cursor c) {
        int first = c.read();
        boolean huffman = (first & 0x80) != 0;
        long rawLen = readInt(c, first & 0x7f, 7);
        if (rawLen > (1L << 23)) throw new IllegalArgumentException("string literal too long");
        int n = (int) rawLen;
        if (!huffman) {
            if (n > c.end - c.pos) throw new IllegalArgumentException("truncated string literal");
            String s = new String(c.buf, c.pos, n, StandardCharsets.UTF_8);
            c.pos += n;
            return s;
        }
        if (n > c.end - c.pos) throw new IllegalArgumentException("truncated huffman literal");
        byte[] out = huffmanDecode(c.buf, c.pos, n);
        c.pos += n;
        return new String(out, StandardCharsets.UTF_8);
    }

    /**
     * RFC 7541 section 5.1 integer: {@code prefix} holds the already-consumed n-bit
     * prefix; when it is all ones, continuation octets (7 bit chunks, MSB continuation
     * flag) follow.
     */
    private static long readInt(Cursor c, int prefix, int n) {
        long limit = (1L << n) - 1;
        long value = prefix;
        if (value < limit) {
            return value;
        }
        long factor = 1;
        while (true) {
            if (c.pos >= c.end) throw new IllegalArgumentException("truncated integer");
            int b = c.buf[c.pos++] & 0xFF;
            value += (b & 0x7F) * factor;
            factor <<= 7;
            if ((b & 0x80) == 0) break;
            if (factor > (1L << 56)) throw new IllegalArgumentException("integer too long");
        }
        return value;
    }

    private static byte[] huffmanDecode(byte[] in, int off, int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(16, n));
        long acc = 0;
        int len = 0;
        for (int i = off; i < off + n; i++) {
            int b = in[i] & 0xFF;
            for (int k = 7; k >= 0; k--) {
                int bit = (b >> k) & 1;
                acc = (acc << 1) | bit;
                len++;
                if (len > 30) throw new IllegalArgumentException("huffman code too long");
                int idx = len - 5;
                if (idx < 0 || len > 30) continue;
                if (idx < CODE_MIN.length && CODE_MAX[idx] < 0) {
                    continue; // no codes at this length
                }
                int v = (int) acc;
                if (v < CODE_MIN[idx] || v > CODE_MAX[idx]) continue;
                Integer sym = HUFF.get(((long) len << 32) | (v & 0xFFFFFFFFL));
                if (sym != null) {
                    if (sym == 256) throw new IllegalArgumentException("EOS symbol in huffman data");
                    out.write(sym);
                    acc = 0;
                    len = 0;
                }
            }
        }
        // remaining bits are padding built from the EOS code prefix; must be < 8 bits total
        if (len > 7) throw new IllegalArgumentException("huffman padding too long (len=" + len + ")");
        return out.toByteArray();
    }

    private static final class Cursor {
        final byte[] buf;
        final int end;
        int pos;

        Cursor(byte[] buf, int off, int end) {
            this.buf = buf;
            this.pos = off;
            this.end = end;
        }

        boolean done() {
            return pos >= end;
        }

        int read() {
            if (pos >= end) throw new IllegalArgumentException("truncated header block");
            return buf[pos++] & 0xFF;
        }
    }
}
