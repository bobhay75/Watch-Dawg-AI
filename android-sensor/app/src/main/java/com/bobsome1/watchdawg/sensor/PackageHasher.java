package com.bobsome1.watchdawg.sensor;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/** Produces device-local pseudonyms so raw package names never leave the app. */
public final class PackageHasher {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "watchdawg.package.hmac.v1";
    private static SecretKey cachedKey;

    private PackageHasher() {}

    public static synchronized String hash(String packageName) throws Exception {
        SecretKey key = getOrCreateKey();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] digest = mac.doFinal(packageName.getBytes(StandardCharsets.UTF_8));
        StringBuilder output = new StringBuilder("pkg-hmac256:");
        for (byte value : digest) {
            output.append(String.format("%02x", value & 0xff));
        }
        return output.toString();
    }

    private static SecretKey getOrCreateKey() throws Exception {
        if (cachedKey != null) {
            return cachedKey;
        }
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            cachedKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
            return cachedKey;
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        cachedKey = generator.generateKey();
        return cachedKey;
    }
}
