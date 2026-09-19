package com.bobsome1.watchdawg.sensor;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Visible control plane for owner-authorized collection, export, and sync. */
public final class MainActivity extends Activity {
    private static final int CREATE_DOCUMENT_REQUEST = 901;
    private static final String USAGE_ACCESS_HELP =
            "Galaxy setup: Android's normal Permissions page can say no permissions are allowed; "
                    + "that is expected because Usage Access is under Special app access. If Android "
                    + "says this setting is restricted, first open "
                    + "Watch-Dawg App Info below, tap the three-dot menu, and choose Allow restricted "
                    + "settings. Return here, open Usage Access, select Watch-Dawg Sensor, and turn it on.";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private TextView status;
    private EditText endpoint;
    private EditText token;
    private String pendingExportText;
    private final EditGeneration tokenEditGeneration = new EditGeneration();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(buildUi());
        refreshStatus("Ready. No scan has been started by this screen.");
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus("Ready.");
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private View buildUi() {
        int padding = dp(18);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);

        TextView title = new TextView(this);
        title.setText("Watch-Dawg Sensor");
        title.setTextSize(26f);
        content.addView(title);

        TextView disclosure = new TextView(this);
        disclosure.setText(
                "Real, non-root Android evidence collection. This app never requests camera or microphone "
                        + "permission and cannot identify another app using those sensors. It can correlate "
                        + "foreground transitions with granted permissions as a clearly labeled capability "
                        + "inference. Package identities are keyed-hashed before export. No action is blocked "
                        + "or remediated automatically.");
        disclosure.setTextSize(15f);
        disclosure.setPadding(0, dp(12), 0, dp(12));
        content.addView(disclosure);

        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setPadding(0, dp(8), 0, dp(12));
        content.addView(status);

        TextView usageHelp = new TextView(this);
        usageHelp.setText(USAGE_ACCESS_HELP);
        usageHelp.setTextSize(15f);
        usageHelp.setPadding(0, 0, 0, dp(8));
        content.addView(usageHelp);

        content.addView(button("1. Open Watch-Dawg App Info", view -> openAppInfo()));
        content.addView(button("2. Open Usage Access", view -> openUsageAccess()));
        content.addView(button("Open Android privacy settings", view -> openPrivacySettings()));
        content.addView(button("Run real scan now", view -> runAsync(
                "Collecting device evidence…",
                () -> {
                    String envelope = SignedSnapshotStore.collectAndSave(getApplicationContext());
                    return "Signed snapshot created (" + envelope.getBytes(StandardCharsets.UTF_8).length
                            + " bytes).";
                })));
        content.addView(button("Export latest signed snapshot", view -> prepareSnapshotExport()));
        content.addView(button("Export enrollment public key", view -> prepareEnrollmentExport()));
        content.addView(button("Copy enrollment record", view -> copyEnrollmentRecord()));
        content.addView(button("Enable 15-minute periodic collection", view -> {
            try {
                CollectionScheduler.enable(getApplicationContext());
                refreshStatus("Periodic collection enabled by owner action.");
            } catch (RuntimeException error) {
                refreshStatus(errorMessage(error));
            }
        }));
        content.addView(button("Disable periodic collection", view -> {
            try {
                CollectionScheduler.disable(getApplicationContext());
                refreshStatus("Periodic collection disabled.");
            } catch (RuntimeException error) {
                refreshStatus(errorMessage(error));
            }
        }));

        TextView syncTitle = new TextView(this);
        syncTitle.setText("Optional signed sync");
        syncTitle.setTextSize(20f);
        syncTitle.setPadding(0, dp(20), 0, dp(4));
        content.addView(syncTitle);

        TextView syncDisclosure = new TextView(this);
        syncDisclosure.setText(
                "Sync is manual and HTTPS-only. Redirects are refused so the bearer credential cannot be "
                        + "silently forwarded. Leaving the token blank preserves an existing saved token.");
        content.addView(syncDisclosure);

        endpoint = new EditText(this);
        endpoint.setHint("https://watch-dawg.example/v1/swarm/snapshot");
        endpoint.setSingleLine(true);
        endpoint.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        endpoint.setText(SyncConfig.endpoint(this));
        content.addView(endpoint);

        token = new EditText(this);
        token.setHint("Device bearer credential");
        token.setSingleLine(true);
        token.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        token.setImeOptions(EditorInfo.IME_ACTION_DONE
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI
                | EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        token.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        token.setSaveEnabled(false);
        token.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(
                    CharSequence value, int start, int count, int after) {}

            @Override
            public void onTextChanged(
                    CharSequence value, int start, int before, int count) {
                tokenEditGeneration.markChanged();
            }

            @Override
            public void afterTextChanged(Editable value) {}
        });
        content.addView(token);

        content.addView(button("Save encrypted sync settings", view -> {
            String endpointValue = endpoint.getText().toString();
            String tokenValue = token.getText().toString();
            long editGeneration = tokenEditGeneration.snapshot();
            runAsync(
                    "Saving sync settings…",
                    () -> {
                        SyncConfig.save(getApplicationContext(), endpointValue, tokenValue);
                        runOnUiThread(() -> {
                            if (tokenEditGeneration.isCurrent(editGeneration)) {
                                token.setText("");
                            }
                        });
                        return "Sync settings saved; bearer credential is protected by Android Keystore.";
                    });
        }));
        content.addView(button("Clear saved bearer credential", view -> {
            token.setText("");
            runAsync(
                    "Clearing saved bearer credential…",
                    () -> {
                        SyncConfig.clearToken(getApplicationContext());
                        return "Saved bearer credential cleared.";
                    });
        }));
        content.addView(button("Sync oldest pending snapshot and verify receipt", view -> runAsync(
                "Sending oldest pending signed snapshot over HTTPS…",
                () -> SyncClient.sendLatest(getApplicationContext()))));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        return scroll;
    }

    private Button button(String label, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(listener);
        LinearLayout.LayoutParams parameters = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        parameters.setMargins(0, dp(4), 0, dp(4));
        button.setLayoutParams(parameters);
        return button;
    }

    private void openUsageAccess() {
        // Android documents ACTION_USAGE_ACCESS_SETTINGS as accepting no input. Some OEM builds,
        // including Samsung releases, reject or mishandle a package URI on this action.
        startSettings(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS));
    }

    private void openAppInfo() {
        Intent intent = new Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:" + getPackageName()));
        startSettings(intent);
    }

    private void openPrivacySettings() {
        startSettings(new Intent(Settings.ACTION_PRIVACY_SETTINGS));
    }

    private void startSettings(Intent intent) {
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException | SecurityException error) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
            } catch (ActivityNotFoundException | SecurityException fallbackError) {
                refreshStatus("Android blocked the requested Settings screen. Open Settings > Apps > "
                        + "Watch-Dawg Sensor manually.");
            }
        }
    }

    private void prepareSnapshotExport() {
        runAsync(
                "Preparing signed snapshot export…",
                () -> {
                    String latest = SignedSnapshotStore.readLatest(getApplicationContext());
                    if (latest.isEmpty()) {
                        throw new IllegalStateException("Run a scan before exporting");
                    }
                    runOnUiThread(() -> launchExport(latest, "watchdawg-signed-snapshot.json"));
                    return "Choose where to save the signed snapshot.";
                });
    }

    private void prepareEnrollmentExport() {
        runAsync(
                "Preparing public enrollment record…",
                () -> {
                    String record = DeviceIdentity.enrollmentRecord();
                    runOnUiThread(() -> launchExport(record, "watchdawg-enrollment.json"));
                    return "Choose where to save the public enrollment record.";
                });
    }

    private void copyEnrollmentRecord() {
        runAsync(
                "Preparing public enrollment record…",
                () -> {
                    String record = DeviceIdentity.enrollmentRecord();
                    runOnUiThread(() -> {
                        ClipboardManager clipboard = (ClipboardManager) getSystemService(
                                Context.CLIPBOARD_SERVICE);
                        if (clipboard != null) {
                            clipboard.setPrimaryClip(ClipData.newPlainText(
                                    "Watch-Dawg enrollment", record));
                        }
                    });
                    return "Public enrollment record copied. It contains no private key.";
                });
    }

    private void launchExport(String text, String fileName) {
        pendingExportText = text;
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, fileName);
        startActivityForResult(intent, CREATE_DOCUMENT_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != CREATE_DOCUMENT_REQUEST || resultCode != RESULT_OK || data == null) {
            return;
        }
        Uri target = data.getData();
        String exportText = pendingExportText;
        pendingExportText = null;
        if (target == null || exportText == null) {
            refreshStatus("Export destination was unavailable.");
            return;
        }
        runAsync(
                "Writing export…",
                () -> {
                    try (OutputStream output = getContentResolver().openOutputStream(target, "wt");
                         OutputStreamWriter writer = output == null
                                 ? null : new OutputStreamWriter(output, StandardCharsets.UTF_8)) {
                        if (writer == null) {
                            throw new IllegalStateException("Could not open export destination");
                        }
                        writer.write(exportText);
                        writer.flush();
                    }
                    return "Export saved.";
                });
    }

    private void runAsync(String startingMessage, Callable<String> operation) {
        status.setText(startingMessage);
        executor.submit(() -> {
            try {
                String message = operation.call();
                runOnUiThread(() -> refreshStatus(message));
            } catch (Exception error) {
                runOnUiThread(() -> refreshStatus(errorMessage(error)));
            }
        });
    }

    private void refreshStatus(String message) {
        boolean usage = SnapshotCollector.hasUsageAccess(this);
        boolean scheduled = CollectionScheduler.isEnabled(this);
        boolean syncConfigured = !SyncConfig.endpoint(this).isEmpty() && SyncConfig.hasToken(this);
        String pending;
        try {
            pending = Long.toString(SignedSnapshotStore.pendingCount(this));
        } catch (Exception error) {
            pending = "unavailable";
        }
        String identity;
        try {
            identity = "\nDevice: " + DeviceIdentity.deviceId()
                    + "\nSigning key: " + DeviceIdentity.keySecurityLevel();
        } catch (Exception error) {
            identity = "\nDevice signing identity: not initialized";
        }
        status.setText(message
                + "\nUsage Access: " + (usage ? "granted" : "not granted")
                + (usage ? "" : "\nNext: complete steps 1 and 2 below. If step 2 is blocked, use "
                        + "App Info > three-dot menu > Allow restricted settings first.")
                + "\nPeriodic collection: " + (scheduled ? "enabled" : "disabled")
                + "\nSigned sync: " + (syncConfigured ? "configured" : "not configured")
                + "\nPending signed snapshots: " + pending
                + identity);
    }

    private static String errorMessage(Throwable error) {
        String message = error.getMessage();
        return "Operation failed: " + (message == null || message.isEmpty()
                ? error.getClass().getSimpleName() : message);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
