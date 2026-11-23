package com.bobsome1.watchdawg.sensor;

import android.content.Context;
import android.util.Base64;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.HttpsURLConnection;

/** Delivers an already-signed envelope over platform-validated TLS. */
public final class SyncClient {
    private static final int MAX_REQUEST_BYTES = 512_000;
    private static final int MAX_RESPONSE_CHARS = 4_096;

    private SyncClient() {}

    public static String sendLatest(Context context) throws Exception {
        String endpoint = SyncConfig.endpoint(context);
        String token = SyncConfig.token(context);
        if (endpoint.isEmpty()) {
            throw new IllegalStateException("Configure an HTTPS sync endpoint first");
        }
        if (token.isEmpty()) {
            throw new IllegalStateException("Configure a bearer credential first");
        }
        if (!SyncConfig.isValidToken(token)) {
            throw new IllegalStateException("Stored bearer credential is invalid");
        }
        SignedSnapshotStore.PendingSnapshot pending =
                SignedSnapshotStore.readOldestPending(context);
        if (pending == null) {
            throw new IllegalStateException("No signed snapshots are pending sync");
        }
        String envelope = pending.envelope();
        byte[] body = envelope.getBytes(StandardCharsets.UTF_8);
        if (body.length > MAX_REQUEST_BYTES) {
            throw new IllegalStateException("Signed snapshot exceeds the sync safety limit");
        }
        RequestIdentity requestIdentity = RequestIdentity.fromEnvelope(envelope);
        if (requestIdentity.sequence != pending.sequence()
                || !requestIdentity.snapshotSha256.equals(pending.payloadSha256())) {
            throw new IllegalStateException(
                    "Pending outbox identity did not match its signed envelope");
        }

        URI uri = URI.create(endpoint);
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || uri.getUserInfo() != null
                || uri.getFragment() != null) {
            throw new IllegalArgumentException("Endpoint must be an HTTPS URL without credentials or a fragment");
        }

        HttpsURLConnection connection = (HttpsURLConnection) uri.toURL().openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(15_000);
        connection.setReadTimeout(20_000);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + token);
        connection.setRequestProperty("X-WatchDawg-Device-ID", requestIdentity.deviceId);
        connection.setFixedLengthStreamingMode(body.length);
        connection.setDoOutput(true);

        try {
            try (OutputStream output = connection.getOutputStream()) {
                output.write(body);
            }
            int status = connection.getResponseCode();
            InputStream responseStream = status == 201
                    ? connection.getInputStream() : connection.getErrorStream();
            String response = readBounded(responseStream);
            if (status != 201) {
                throw new IllegalStateException("Server rejected snapshot (HTTP " + status + ")");
            }
            String contentType = connection.getContentType();
            if (contentType == null
                    || !"application/json".equalsIgnoreCase(contentType.split(";", 2)[0].trim())) {
                throw new IllegalStateException("Server receipt was not JSON");
            }
            verifyReceipt(response, requestIdentity);
            // Deletion happens only after an exact 201 receipt was type-checked and
            // bound to the queued sequence and payload hash. The store reopens the
            // exact entry under its mutation lock before deleting it.
            SignedSnapshotStore.acknowledgePending(context, pending);
            int remaining = SignedSnapshotStore.pendingCount(context);
            return "Bound server receipt verified for sequence " + requestIdentity.sequence
                    + " (SHA-256 " + requestIdentity.snapshotSha256.substring(0, 16)
                    + "…). Pending snapshots: " + remaining + ".";
        } finally {
            connection.disconnect();
        }
    }

    private static void verifyReceipt(String response, RequestIdentity expected) throws Exception {
        JSONObject receipt = new JSONObject(response);
        Object accepted = receipt.opt("accepted");
        Object deviceId = receipt.opt("device_id");
        Object keyId = receipt.opt("key_id");
        Object sequence = receipt.opt("sequence");
        Object snapshotSha256 = receipt.opt("snapshot_sha256");
        boolean exactFields = receipt.length() == 5
                && receipt.has("accepted")
                && receipt.has("device_id")
                && receipt.has("key_id")
                && receipt.has("sequence")
                && receipt.has("snapshot_sha256");
        boolean integralSequence = sequence instanceof Integer || sequence instanceof Long;
        boolean matches = exactFields
                && Boolean.TRUE.equals(accepted)
                && deviceId instanceof String
                && expected.deviceId.equals(deviceId)
                && keyId instanceof String
                && expected.keyId.equals(keyId)
                && integralSequence
                && expected.sequence == ((Number) sequence).longValue()
                && snapshotSha256 instanceof String
                && expected.snapshotSha256.equals(snapshotSha256);
        if (!matches) {
            throw new IllegalStateException("Server receipt did not match the signed snapshot");
        }
    }

    private static String readBounded(InputStream input) throws Exception {
        if (input == null) {
            return "";
        }
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(input, StandardCharsets.UTF_8))) {
            char[] buffer = new char[512];
            int count;
            while ((count = reader.read(buffer)) >= 0) {
                if (output.length() + count > MAX_RESPONSE_CHARS) {
                    throw new IllegalStateException("Server response exceeded the safety limit");
                }
                output.append(buffer, 0, count);
            }
        }
        return output.toString().trim();
    }

    private static final class RequestIdentity {
        private final String deviceId;
        private final String keyId;
        private final long sequence;
        private final String snapshotSha256;

        private RequestIdentity(
                String deviceId,
                String keyId,
                long sequence,
                String snapshotSha256) {
            this.deviceId = deviceId;
            this.keyId = keyId;
            this.sequence = sequence;
            this.snapshotSha256 = snapshotSha256;
        }

        private static RequestIdentity fromEnvelope(String envelopeText) throws Exception {
            JSONObject envelope = new JSONObject(envelopeText);
            if (envelope.optInt("schema_version", -1) != 1
                    || !DeviceIdentity.ALGORITHM.equals(envelope.optString("algorithm", ""))) {
                throw new IllegalStateException("Stored snapshot envelope has an unsupported schema");
            }
            String deviceId = envelope.getString("device_id");
            String keyId = envelope.getString("key_id");
            if (!DeviceIdentity.deviceId().equals(deviceId)
                    || !DeviceIdentity.keyId().equals(keyId)) {
                throw new IllegalStateException("Stored snapshot does not match this device identity");
            }
            byte[] signedPayload = Base64.decode(
                    envelope.getString("signed_payload"), Base64.NO_WRAP);
            JSONObject payload = new JSONObject(
                    new String(signedPayload, StandardCharsets.UTF_8));
            long sequence = payload.optLong("sequence", -1L);
            if (sequence < 1L || !deviceId.equals(payload.optString("device_id", ""))) {
                throw new IllegalStateException("Stored signed payload identity is invalid");
            }
            return new RequestIdentity(
                    deviceId,
                    keyId,
                    sequence,
                    DeviceIdentity.sha256Hex(signedPayload));
        }
    }
}
