package com.bobsome1.watchdawg.sensor;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

/** Owns the non-exportable Android Keystore signing identity. */
public final class DeviceIdentity {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "watchdawg.snapshot.signing.v1";
    public static final String ALGORITHM = "SHA256withECDSA";

    private DeviceIdentity() {}

    public static synchronized void ensureKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateKey(true);
                return;
            } catch (StrongBoxUnavailableException unavailable) {
                // Fall through to the TEE/software-backed provider selected by Android.
            }
        }
        generateKey(false);
    }

    private static void generateKey(boolean preferStrongBox) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && preferStrongBox) {
            builder.setIsStrongBoxBacked(true);
        }
        generator.initialize(builder.build());
        generator.generateKeyPair();
    }

    public static PublicKey publicKey() throws Exception {
        ensureKey();
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore.getCertificate(KEY_ALIAS).getPublicKey();
    }

    private static PrivateKey privateKey() throws Exception {
        ensureKey();
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
    }

    public static byte[] sign(byte[] payload) throws Exception {
        Signature signer = Signature.getInstance(ALGORITHM);
        signer.initSign(privateKey());
        signer.update(payload);
        return signer.sign();
    }

    static boolean verify(byte[] payload, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey());
        verifier.update(payload);
        return verifier.verify(signature);
    }

    public static String keyId() throws Exception {
        return sha256Hex(publicKey().getEncoded());
    }

    public static String deviceId() throws Exception {
        return "android-" + keyId().substring(0, 24);
    }

    public static String enrollmentRecord() throws Exception {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("device_id", deviceId());
        record.put("key_id", keyId());
        record.put("public_key_der_base64", Base64.encodeToString(
                publicKey().getEncoded(), Base64.NO_WRAP));
        return CanonicalJson.encode(record);
    }

    public static String keySecurityLevel() {
        try {
            PrivateKey key = privateKey();
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEYSTORE);
            KeyInfo info = factory.getKeySpec(key, KeyInfo.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                        return "strongbox";
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                        return "trusted_environment";
                    case KeyProperties.SECURITY_LEVEL_SOFTWARE:
                        return "software";
                    default:
                        return "unknown";
                }
            }
            return info.isInsideSecureHardware() ? "secure_hardware" : "software";
        } catch (Exception error) {
            return "unknown";
        }
    }

    public static String sha256Hex(byte[] input) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
        StringBuilder output = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            output.append(String.format("%02x", value & 0xff));
        }
        return output.toString();
    }

    public static Map<String, Object> envelope(String canonicalPayload) throws Exception {
        byte[] payloadBytes = canonicalPayload.getBytes(StandardCharsets.UTF_8);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema_version", 1L);
        envelope.put("device_id", deviceId());
        envelope.put("key_id", keyId());
        envelope.put("algorithm", ALGORITHM);
        envelope.put("signed_payload", Base64.encodeToString(payloadBytes, Base64.NO_WRAP));
        envelope.put("signature", Base64.encodeToString(sign(payloadBytes), Base64.NO_WRAP));
        return envelope;
    }
}
