package com.ecapture.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import com.ecapture.burp.ui.ECaptureTab;

/**
 * Burp Suite extension entry point.
 *
 * <p>Adds an "eCapture" tab that connects to eCapture's eCaptureQ WebSocket stream
 * (ecapture tls -m text --ecaptureq=ws://127.0.0.1:28257/), decodes the protobuf
 * events and reconstructs HTTP requests/responses so they can be viewed and
 * forwarded to Repeater, Intruder, Comparer and the site map.
 */
public final class ECaptureBurpExtension implements BurpExtension {

    public static final String AUTHOR_URL = "https://sunny.onl";

    private ECaptureTab tab;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("eCapture");
        try {
            tab = new ECaptureTab(api);
            api.userInterface().registerSuiteTab("eCapture", tab.component());
            api.logging().logToOutput("eCapture extension loaded (tab 'eCapture')");
            api.logging().logToOutput("Created by Sunny - " + AUTHOR_URL);
        } catch (Throwable t) {
            api.logging().logToError("failed to register eCapture tab: " + t);
        }
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override public void extensionUnloaded() {
                if (tab != null) {
                    tab.shutdown();
                }
            }
        });
    }
}
