package com.bobsome1.watchdawg.sensor;

import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/** Verified identity extracted from one locally signed snapshot envelope. */
final class SnapshotEnvelope {
    final String text;
    final byte[] encoded;
    final long sequence;
    final String payloadSha256;

    private SnapshotEnvelope(
            String text, byte[] encoded, long sequence, String payloadSha256) {
        this.text = text;
        this.encoded = encoded.clone();
        this.sequence = sequence;
        this.payloadSha256 = payloadSha256;
    }

    static SnapshotEnvelope verify(byte[] encoded) throws Exception {
        if (encoded == null || encoded.length == 0
                || encoded.length > SignedSnapshotStore.MAX_STORED_BYTES) {
            throw new IllegalStateException("Signed snapshot envelope size is invalid");
        }
        String text = new String(encoded, StandardCharsets.UTF_8);
        JSONObject envelope = new JSONObject(text);
        if (envelope.length() != 6
                || !hasExactEnvelopeFields(envelope)
                || !isIntegerOne(envelope.opt("schema_version"))
                || !DeviceIdentity.ALGORITHM.equals(envelope.opt("algorithm"))) {
            throw new IllegalStateException("Signed snapshot envelope schema is invalid");
        }
        Object deviceIdValue = envelope.opt("device_id");
        Object keyIdValue = envelope.opt("key_id");
        Object payloadValue = envelope.opt("signed_payload");
        Object signatureValue = envelope.opt("signature");
        if (!(deviceIdValue instanceof String)
                || !(keyIdValue instanceof String)
                || !(payloadValue instanceof String)
                || !(signatureValue instanceof String)) {
            throw new IllegalStateException("Signed snapshot envelope types are invalid");
        }
        String deviceId = (String) deviceIdValue;
        String keyId = (String) keyIdValue;
        if (!DeviceIdentity.deviceId().equals(deviceId)
                || !DeviceIdentity.keyId().equals(keyId)) {
            throw new IllegalStateException(
                    "Signed snapshot envelope belongs to another device identity");
        }

        byte[] signedPayload;
        byte[] signature;
        try {
            signedPayload = Base64.decode((String) payloadValue, Base64.NO_WRAP);
            signature = Base64.decode((String) signatureValue, Base64.NO_WRAP);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalStateException("Signed snapshot envelope base64 is invalid", malformed);
        }
        if (!DeviceIdentity.verify(signedPayload, signature)) {
            throw new IllegalStateException("Stored snapshot signature verification failed");
        }

        JSONObject payload = new JSONObject(
                new String(signedPayload, StandardCharsets.UTF_8));
        Object sequenceValue = payload.opt("sequence");
        boolean integralSequence = sequenceValue instanceof Integer
                || sequenceValue instanceof Long;
        long sequence = integralSequence ? ((Number) sequenceValue).longValue() : -1L;
        if (sequence < 1L || !deviceId.equals(payload.opt("device_id"))) {
            throw new IllegalStateException("Signed snapshot payload identity is invalid");
        }
        return new SnapshotEnvelope(
                text,
                encoded,
                sequence,
                DeviceIdentity.sha256Hex(signedPayload));
    }

    private static boolean hasExactEnvelopeFields(JSONObject envelope) {
        return envelope.has("schema_version")
                && envelope.has("device_id")
                && envelope.has("key_id")
                && envelope.has("algorithm")
                && envelope.has("signed_payload")
                && envelope.has("signature");
    }

    private static boolean isIntegerOne(Object value) {
        return (value instanceof Integer || value instanceof Long)
                && ((Number) value).longValue() == 1L;
    }
}
