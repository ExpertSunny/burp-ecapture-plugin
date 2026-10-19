package com.ecapture.burp.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import com.ecapture.burp.AssembleEngine;
import com.ecapture.burp.ECaptureBurpExtension;
import com.ecapture.burp.CaptureItem;
import com.ecapture.burp.ws.ECaptureQClient;
import com.ecapture.burp.pb.LogEntry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * The "eCapture" suite tab: connection controls, capture table, message viewers,
 * console log, and the "send to" actions bridging captured messages into Burp tools.
 */
public final class ECaptureTab {

    private static final String PREF_HOST = "ecapture.burp.host";
    private static final String PREF_PORT = "ecapture.burp.port";
    private static final int DISPLAY_CAP = 256 * 1024;

    private final MontoyaApi api;
    private AssembleEngine engine;
    private ECaptureQClient client;

    private final JPanel root = new JPanel(new BorderLayout());

    // connection row
    private JTextField hostField;
    private JTextField portField;
    private JButton connectBtn;
    private JButton disconnectBtn;
    private JLabel statusLabel;

    // capture area
    private AssembleEngine.Listener engineListener;
    private TabModel model;
    private JTable table;
    private JTabbedPane tabs;      // Capture / Console
    private JTextArea requestView;
    private JTextArea responseView;
    private JTabbedPane msgTabs;   // Request / Response
    private JTextArea console;
    private JToggleButton hexToggle;
    private JToggleButton pauseToggle;
    private JComboBox<String> kindFilter;
    private JTextField procFilter;

    private CaptureItem selected;
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final Deque<PendingUI> pausedQueue = new ArrayDeque<>();
    private static final int PAUSED_QUEUE_MAX = 5000;

    public ECaptureTab(MontoyaApi api) {
        this.api = api;
        engineListener = new SwingListener();
        engine = new AssembleEngine(engineListener);
        buildUi();
        loadPrefs();
    }

    public Component component() {
        return root;
    }

    public void shutdown() {
        if (client != null) {
            client.disconnect();
        }
        savePrefs();
    }

    // ------------------------------------------------------------------ UI

    private void buildUi() {
        root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // connection row
        JPanel connRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        connRow.add(new JLabel("Device (ws host):"));
        hostField = new JTextField("127.0.0.1", 12);
        connRow.add(hostField);
        connRow.add(new JLabel("Port:"));
        portField = new JTextField("28257", 6);
        connRow.add(portField);
        connectBtn = new JButton("Connect");
        connectBtn.addActionListener(e -> doConnect());
        connRow.add(connectBtn);
        disconnectBtn = new JButton("Disconnect");
        disconnectBtn.setEnabled(false);
        disconnectBtn.addActionListener(e -> doDisconnect());
        connRow.add(disconnectBtn);

        // filter row
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filterRow.add(new JLabel("Kind:"));
        kindFilter = new JComboBox<>(new String[]{"All", "HTTP/1", "HTTP/2", "PUSH", "RAW"});
        kindFilter.addActionListener(e -> reapplyFilter());
        filterRow.add(kindFilter);
        filterRow.add(new JLabel("Process contains:"));
        procFilter = new JTextField(14);
        procFilter.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { reapplyFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { reapplyFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { reapplyFilter(); }
        });
        filterRow.add(procFilter);
        pauseToggle = new JToggleButton("Pause");
        pauseToggle.addActionListener(e -> {
            boolean on = pauseToggle.isSelected();
            paused.set(on);
            if (!on) {
                flushPaused();
            }
        });
        filterRow.add(pauseToggle);
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> doClear());
        filterRow.add(clearBtn);

        // Burp disables HTML in Swing labels, so style the link by hand
        JLabel credit = new JLabel("by sunny.onl");
        java.util.Map<java.awt.font.TextAttribute, Object> underline = new HashMap<>();
        underline.put(java.awt.font.TextAttribute.UNDERLINE, java.awt.font.TextAttribute.UNDERLINE_ON);
        credit.setFont(credit.getFont().deriveFont(underline));
        credit.setForeground(new java.awt.Color(0x4A9EFF));
        credit.setToolTipText(ECaptureBurpExtension.AUTHOR_URL);
        credit.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        credit.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 8));
        credit.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                try {
                    java.awt.Desktop.getDesktop().browse(java.net.URI.create(ECaptureBurpExtension.AUTHOR_URL));
                } catch (Exception ex) {
                    logLine("[ui] open " + ECaptureBurpExtension.AUTHOR_URL + " failed: " + ex);
                }
            }
        });
        JPanel connBar = new JPanel(new BorderLayout());
        connBar.add(connRow, BorderLayout.CENTER);
        connBar.add(credit, BorderLayout.EAST);

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(connBar);
        north.add(filterRow);
        root.add(north, BorderLayout.NORTH);

        // table
        model = new TabModel();
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowSorter(null);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(140);
        table.getColumnModel().getColumn(2).setPreferredWidth(150);
        table.getColumnModel().getColumn(3).setPreferredWidth(170);
        table.getColumnModel().getColumn(4).setPreferredWidth(70);
        table.getColumnModel().getColumn(5).setPreferredWidth(420);
        table.getColumnModel().getColumn(6).setPreferredWidth(90);
        table.getColumnModel().getColumn(7).setPreferredWidth(90);
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    syncSelection();
                }
            }
        });
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) syncSelection();
        });
        JScrollPane tableScroll = new JScrollPane(table);

        // viewer
        requestView = monoArea();
        responseView = monoArea();
        msgTabs = new JTabbedPane();
        msgTabs.addTab("Request", new JScrollPane(requestView));
        msgTabs.addTab("Response", new JScrollPane(responseView));

        hexToggle = new JToggleButton("Hex");
        hexToggle.addActionListener(e -> syncSelection());

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton repeaterBtn = new JButton("Send to Repeater");
        repeaterBtn.addActionListener(e -> sendRepeater());
        actionRow.add(repeaterBtn);
        JButton intruderBtn = new JButton("Intruder");
        intruderBtn.addActionListener(e -> sendIntruder());
        actionRow.add(intruderBtn);
        JButton comparerBtn = new JButton("Comparer");
        comparerBtn.addActionListener(e -> sendComparer());
        actionRow.add(comparerBtn);
        JButton siteMapBtn = new JButton("Add to site map");
        siteMapBtn.addActionListener(e -> sendSiteMap());
        actionRow.add(siteMapBtn);
        actionRow.add(hexToggle);

        JPanel detail = new JPanel(new BorderLayout());
        detail.add(actionRow, BorderLayout.NORTH);
        detail.add(msgTabs, BorderLayout.CENTER);

        JSplitPane captureSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detail);
        captureSplit.setResizeWeight(0.55);

        console = monoArea();
        JScrollPane consoleScroll = new JScrollPane(console);
        tabs = new JTabbedPane();
        tabs.addTab("Capture", captureSplit);
        tabs.addTab("Console", consoleScroll);
        root.add(tabs, BorderLayout.CENTER);

        statusLabel = new JLabel("disconnected");
        root.add(statusLabel, BorderLayout.SOUTH);
    }

    private JTextArea monoArea() {
        JTextArea a = new JTextArea();
        a.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        a.setEditable(false);
        a.setLineWrap(false);
        return a;
    }

    // ------------------------------------------------------------------ model

    private static final class TabModel extends AbstractTableModel {
        final List<CaptureItem> rows = new ArrayList<>();
        private static final String[] COLS = {"#", "Time", "Process", "Server", "Type", "Summary", "Req", "Resp"};

        @Override public int getRowCount() { return rows.size(); }

        @Override public int getColumnCount() { return COLS.length; }

        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override public Object getValueAt(int r, int c) {
            CaptureItem it = rows.get(r);
            switch (c) {
                case 0: return it.id;
                case 1: return fmtTime(it.ts);
                case 2: return it.pname.isEmpty() ? ("pid " + it.pid) : it.pname + " (" + it.pid + ")";
                case 3: return it.serverAddr.isEmpty() ? "-" : it.serverAddr;
                case 4: return it.kind;
                case 5: return it.summary + (it.truncated ? "  [TRUNCATED]" : "")
                    + (it.responseComplete ? "" : (it.hasResponse() ? "  (open)" : "  (no response yet)"));
                case 6: return it.requestLen() > 0 ? CaptureItem.formatK(it.requestLen()) : "-";
                case 7: return it.responseLen() > 0 ? CaptureItem.formatK(it.responseLen()) : "-";
                default: return "";
            }
        }

        @Override public Class<?> getColumnClass(int c) {
            return c == 0 ? Integer.class : String.class;
        }
    }

    private static String fmtTime(long ms) {
        return new java.text.SimpleDateFormat("HH:mm:ss.SSS").format(new java.util.Date(ms));
    }

    // ------------------------------------------------------------------ engine bridge

    private final class SwingListener implements AssembleEngine.Listener {
        @Override public void onNewItem(CaptureItem item) {
            invoke(() -> {
                if (accept(item)) {
                    model.rows.add(item);
                    model.fireTableRowsInserted(model.rows.size() - 1, model.rows.size() - 1);
                }
            }, item);
        }

        @Override public void onUpdatedItem(CaptureItem item) {
            invoke(() -> {
                int idx = findRow(item.id);
                if (idx >= 0) {
                    model.fireTableRowsUpdated(idx, idx);
                    if (selected == item) {
                        renderDetails(item);
                    } else if (idx == table.getSelectedRow()) {
                        renderDetails(item);
                    }
                }
            }, item);
        }
    }

    /** UI task while paused: buffer up to a cap so the machine stays responsive. */
    private void invoke(Runnable r, CaptureItem item) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
            return;
        }
        SwingUtilities.invokeLater(() -> {
            if (paused.get() && pausedQueue.size() < PAUSED_QUEUE_MAX) {
                pausedQueue.add(new PendingUI(r));
            } else {
                r.run();
            }
        });
    }

    private void flushPaused() {
        PendingUI p;
        while ((p = pausedQueue.poll()) != null) {
            p.run();
        }
    }

    private static final class PendingUI {
        final Runnable r;

        PendingUI(Runnable r) {
            this.r = r;
        }

        void run() {
            r.run();
        }
    }

    private boolean accept(CaptureItem it) {
        if (model.rows.size() > 20000) {
            model.rows.remove(0);
            model.fireTableDataChanged();
        }
        int kf = kindFilter.getSelectedIndex();
        if (kf > 0) {
            String want = (String) kindFilter.getSelectedItem();
            if (!want.equals(it.kind)) return false;
        }
        String proc = procFilter.getText().trim().toLowerCase();
        if (!proc.isEmpty()) {
            String hay = (it.pname + " " + it.pid).toLowerCase();
            if (!hay.contains(proc)) return false;
        }
        return true;
    }

    private int findRow(int id) {
        for (int i = 0; i < model.rows.size(); i++) {
            if (model.rows.get(i).id == id) return i;
        }
        return -1;
    }

    private void reapplyFilter() {
        SwingUtilities.invokeLater(() -> model.fireTableDataChanged());
        // filter is applied for NEW insertions; existing rows stay (cheap approach)
    }

    private void doClear() {
        engine.clear();
        model.rows.clear();
        model.fireTableDataChanged();
        selected = null;
        requestView.setText("");
        responseView.setText("");
        fireStatus("cleared", "cleared");
    }

    // ------------------------------------------------------------------ connect

    private void doConnect() {
        String host = hostField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException ex) {
            port = 28257;
        }
        if (host.isEmpty()) host = "127.0.0.1";
        savePrefs();
        if (client != null) {
            client.disconnect();
        }
        fireStatus("connecting...", "connecting to ws://" + host + ":" + port + "/");
        client = new ECaptureQClient(host, port, new ECaptureQClient.Handler() {
            @Override public void onProcessLog(String line) {
                logLine("[log] " + line);
            }

            @Override public void onHeartbeat(long ts, long count, String message) {
                fireStatus("connected, " + count + " hb", "servers: " + message);
            }

            @Override public void onEvent(LogEntry.EventBus event) {
                engine.onEvent(event);
            }

            @Override public void onState(boolean connected, String detail) {
                SwingUtilities.invokeLater(() -> {
                    connectBtn.setEnabled(!connected);
                    disconnectBtn.setEnabled(connected);
                    statusLabel.setText(detail);
                    if (!connected) {
                        logLine("[ws] " + detail);
                    }
                });
            }
        });
        client.connect();
    }

    private void doDisconnect() {
        if (client != null) {
            client.disconnect();
        }
    }

    private void fireStatus(String status, String detail) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(status + " — " + detail));
    }

    private void logLine(String line) {
        SwingUtilities.invokeLater(() -> {
            console.append(line.endsWith("\n") ? line : line + "\n");
            if (console.getDocument().getLength() > 2_000_000) {
                console.setText("");
            }
        });
    }

    private void loadPrefs() {
        try {
            String h = api.persistence().preferences().getString(PREF_HOST);
            String p = api.persistence().preferences().getString(PREF_PORT);
            if (h != null && !h.isEmpty()) hostField.setText(h);
            if (p != null && !p.isEmpty()) portField.setText(p);
        } catch (Throwable ignored) {
        }
    }

    private void savePrefs() {
        try {
            api.persistence().preferences().setString(PREF_HOST, hostField.getText().trim());
            api.persistence().preferences().setString(PREF_PORT, portField.getText().trim());
        } catch (Throwable ignored) {
        }
    }

    // ------------------------------------------------------------------ selection & actions

    private void syncSelection() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            selected = null;
            return;
        }
        int row = table.convertRowIndexToModel(viewRow);
        selected = model.rows.get(row);
        renderDetails(selected);
    }

    private void renderDetails(CaptureItem it) {
        if (it == null) return;
        setView(requestView, it.rawRequest, hexToggle.isSelected());
        setView(responseView, it.rawResponse, hexToggle.isSelected());
    }

    private static void setView(JTextArea area, byte[] bytes, boolean hex) {
        if (bytes == null || bytes.length == 0) {
            area.setText("");
            return;
        }
        int cap = Math.min(DISPLAY_CAP, bytes.length);
        byte[] slice = new byte[cap];
        System.arraycopy(bytes, 0, slice, 0, cap);
        String text = hex ? hexDump(slice) : new String(slice, StandardCharsets.ISO_8859_1);
        if (cap < bytes.length) {
            text += "\n... [truncated for display, full content available via actions]";
        }
        area.setText(text);
        area.setCaretPosition(0);
    }

    static String hexDump(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 4);
        for (int i = 0; i < b.length; i += 16) {
            sb.append(String.format("%08x  ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < b.length) {
                    sb.append(String.format("%02x ", b[i + j] & 0xFF));
                } else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(' ');
            }
            sb.append(' ');
            for (int j = 0; j < 16 && i + j < b.length; j++) {
                int c = b[i + j] & 0xFF;
                sb.append(c >= 0x20 && c < 0x7F ? (char) c : '.');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    // HttpService from the selected item
    private HttpService serviceOf(CaptureItem it) {
        String host = it.host;
        int port = 443;
        String sa = it.serverAddr;
        int c = sa.lastIndexOf(':');
        try {
            if (c >= 0 && sa.indexOf(']') < c) {
                port = Integer.parseInt(sa.substring(c + 1));
            }
        } catch (NumberFormatException ignored) {
        }
        if (host.endsWith(":" + port)) {
            host = host.substring(0, host.length() - (":" + port).length());
        }
        if (host.isEmpty()) {
            host = c > 0 ? sa.substring(0, c) : sa;
        }
        boolean secure = port == 443;
        return HttpService.httpService(host, port, secure);
    }

    private List<CaptureItem> selectedItems() {
        int[] vr = table.getSelectedRows();
        List<CaptureItem> out = new ArrayList<>();
        for (int i : vr) {
            out.add(model.rows.get(table.convertRowIndexToModel(i)));
        }
        if (out.isEmpty() && selected != null) {
            out.add(selected);
        }
        return out;
    }

    private HttpRequest buildHttpRequest(CaptureItem it) {
        HttpService svc = serviceOf(it);
        boolean h2 = "HTTP/2".equals(it.kind) || "PUSH".equals(it.kind);
        if (h2 && it.h2reqHeaders != null) {
            List<HttpHeader> hs = new ArrayList<>();
            for (String[] h : it.h2reqHeaders) {
                hs.add(HttpHeader.httpHeader(h[0], h[1]));
            }
            byte[] body = it.h2reqBody == null ? new byte[0] : it.h2reqBody;
            return HttpRequest.http2Request(svc, hs, ByteArray.byteArray(body));
        }
        byte[] raw = it.rawRequest == null ? new byte[0] : it.rawRequest;
        return HttpRequest.httpRequest(svc, new String(raw, StandardCharsets.UTF_8));
    }

    private HttpResponse buildHttpResponse(CaptureItem it) {
        if (it.rawResponse == null || it.rawResponse.length == 0) {
            return null;
        }
        return HttpResponse.httpResponse(ByteArray.byteArray(it.rawResponse));
    }

    private void sendRepeater() {
        List<CaptureItem> sel = selectedItems();
        for (CaptureItem it : sel) {
            try {
                HttpRequest req = buildHttpRequest(it);
                api.repeater().sendToRepeater(req, "ecap-" + it.id);
            } catch (Throwable t) {
                logLine("[action] repeater failed for #" + it.id + ": " + t);
            }
        }
        fireStatus("repeater", "sent " + sel.size() + " request(s)");
    }

    private void sendIntruder() {
        for (CaptureItem it : selectedItems()) {
            try {
                api.intruder().sendToIntruder(buildHttpRequest(it));
            } catch (Throwable t) {
                logLine("[action] intruder failed for #" + it.id + ": " + t);
            }
        }
    }

    private void sendComparer() {
        List<ByteArray> chunks = new ArrayList<>();
        for (CaptureItem it : selectedItems()) {
            if (it.rawRequest != null && it.rawRequest.length > 0) {
                chunks.add(ByteArray.byteArray(it.rawRequest));
            }
            if (it.rawResponse != null && it.rawResponse.length > 0) {
                chunks.add(ByteArray.byteArray(it.rawResponse));
            }
        }
        if (!chunks.isEmpty()) {
            api.comparer().sendToComparer(chunks.toArray(new ByteArray[0]));
        }
    }

    private void sendSiteMap() {
        for (CaptureItem it : selectedItems()) {
            try {
                HttpRequest req = buildHttpRequest(it);
                HttpResponse resp = buildHttpResponse(it);
                if (resp == null) {
                    resp = HttpResponse.httpResponse("HTTP/1.1 200 OK");
                }
                api.siteMap().add(HttpRequestResponse.httpRequestResponse(req, resp));
            } catch (Throwable t) {
                logLine("[action] site map failed for #" + it.id + ": " + t);
            }
        }
        fireStatus("site map", "added items");
    }
}
