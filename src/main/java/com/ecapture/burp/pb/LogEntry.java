package com.ecapture.burp.pb;

/**
 * One decoded eCaptureQ entry. See ecaptureprotobuf/proto/v1/ecaptureq.proto:
 *
 * message LogEntry { LogType log_type = 1; oneof payload { Event event_payload = 2;
 * Heartbeat heartbeat_payload = 3; string run_log = 4; } }
 */
public final class LogEntry {
    public static final int HEARTBEAT = 0;
    public static final int PROCESS_LOG = 1;
    public static final int EVENT = 2;

    // proto3 omits enum fields at their default, so a missing log_type means HEARTBEAT (0)
    public int logType = HEARTBEAT;
    public byte[] runLog;
    public Heartbeat heartbeat;
    public EventBus event;

    public static LogEntry decode(byte[] wire) {
        LogEntry entry = new LogEntry();
        PbReader r = new PbReader(wire);
        while (r.hasField()) {
            switch (r.field()) {
                case 1:
                    entry.logType = (int) r.readVarInt();
                    break;
                case 2:
                    entry.event = EventBus.decode(r.sub());
                    break;
                case 3:
                    entry.heartbeat = Heartbeat.decode(r.sub());
                    break;
                case 4:
                    entry.runLog = r.bytes();
                    break;
                default:
                    r.skip();
            }
        }
        return entry;
    }

    public String runLogText() {
        return runLog == null ? "" : new String(runLog, java.nio.charset.StandardCharsets.UTF_8);
    }

    /** message Event { ... } */
    public static final class EventBus {
        public long timestamp; // 1
        public String uuid = ""; // 2
        public String srcIp = ""; // 3
        public long srcPort; // 4
        public String dstIp = ""; // 5
        public long dstPort; // 6
        public long pid; // 7
        public String pname = ""; // 8
        public long type; // 9
        public long length; // 10
        public byte[] payload = new byte[0]; // 11
        public int captureFormat; // 12
        public int sensitivity; // 13
        public String direction = ""; // 14
        public long originalLength; // 15
        public String streamId = ""; // 16
        public long sequence; // 17

        /** Not on the wire: overrides the engine's connection key (set for legacy events). */
        public String connKey;

        int len() {
            return payload.length;
        }

        static EventBus decode(PbReader r) {
            EventBus e = new EventBus();
            while (r.hasField()) {
                switch (r.field()) {
                    case 1:
                        e.timestamp = r.readVarInt();
                        break;
                    case 2:
                        e.uuid = r.string();
                        break;
                    case 3:
                        e.srcIp = r.string();
                        break;
                    case 4:
                        e.srcPort = r.readVarInt();
                        break;
                    case 5:
                        e.dstIp = r.string();
                        break;
                    case 6:
                        e.dstPort = r.readVarInt();
                        break;
                    case 7:
                        e.pid = r.readVarInt();
                        break;
                    case 8:
                        e.pname = r.string();
                        break;
                    case 9:
                        e.type = r.readVarInt();
                        break;
                    case 10:
                        e.length = r.readVarInt();
                        break;
                    case 11:
                        e.payload = r.bytes();
                        break;
                    case 12:
                        e.captureFormat = (int) r.readVarInt();
                        break;
                    case 13:
                        e.sensitivity = (int) r.readVarInt();
                        break;
                    case 14:
                        e.direction = r.string();
                        break;
                    case 15:
                        e.originalLength = r.readVarInt();
                        break;
                    case 16:
                        e.streamId = r.string();
                        break;
                    case 17:
                        e.sequence = r.readVarInt();
                        break;
                    default:
                        r.skip();
                }
            }
            return e;
        }
    }

    /** message Heartbeat { int64 timestamp = 1; int64 count = 2; string message = 3; } */
    public static final class Heartbeat {
        public long timestamp; // 1
        public long count; // 2
        public String message = ""; // 3

        static Heartbeat decode(PbReader r) {
            Heartbeat h = new Heartbeat();
            while (r.hasField()) {
                switch (r.field()) {
                    case 1:
                        h.timestamp = r.readVarInt();
                        break;
                    case 2:
                        h.count = r.readVarInt();
                        break;
                    case 3:
                        h.message = r.string();
                        break;
                    default:
                        r.skip();
                }
            }
            return h;
        }
    }
}
