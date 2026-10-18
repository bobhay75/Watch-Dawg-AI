package com.bobsome1.watchdawg.sensor;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.net.URI;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Stores the sync endpoint and encrypts the bearer credential with Android Keystore. */
public final class SyncConfig {
    private static final String PREFERENCES = "watchdawg_sync";
    private static final String ENDPOINT = "endpoint";
    private static final String TOKEN_CIPHERTEXT = "token_ciphertext";
    private static final String TOKEN_IV = "token_iv";
    private static final String KEY_ALIAS = "watchdawg.sync.token.v1";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final int MIN_TOKEN_LENGTH = 32;
    private static final int MAX_TOKEN_LENGTH = 256;

    private SyncConfig() {}

    public static void save(Context context, String endpoint, String token) throws Exception {
        String normalizedEndpoint = endpoint == null ? "" : endpoint.trim();
        if (normalizedEndpoint.length() > 2_048) {
            throw new IllegalArgumentException("Sync endpoint is too long");
        }
        if (!normalizedEndpoint.isEmpty()) {
            URI uri = URI.create(normalizedEndpoint);
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null
                    || uri.getUserInfo() != null
                    || uri.getFragment() != null) {
                throw new IllegalArgumentException(
                        "Sync endpoint must be an HTTPS URL without credentials or a fragment");
            }
        }

        SharedPreferences preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
        String previousEndpoint = preferences.getString(ENDPOINT, "");
        SharedPreferences.Editor editor = preferences.edit().putString(ENDPOINT, normalizedEndpoint);
        if (token == null || token.isEmpty()) {
            if (preferences.contains(TOKEN_CIPHERTEXT)
                    && !normalizedEndpoint.equals(previousEndpoint)) {
                throw new IllegalArgumentException(
                        "Re-enter the bearer credential when changing the endpoint");
            }
            if (!preferences.contains(TOKEN_CIPHERTEXT)) {
                editor.remove(TOKEN_CIPHERTEXT).remove(TOKEN_IV);
            }
        } else {
            if (!isValidToken(token)) {
                throw new IllegalArgumentException(
                        "Bearer credential must contain 32-256 URL-safe ASCII characters "
                                + "(letters, numbers, underscore, or hyphen)");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
            cipher.updateAAD(normalizedEndpoint.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
            editor.putString(TOKEN_CIPHERTEXT,
                    Base64.encodeToString(ciphertext, Base64.NO_WRAP));
            editor.putString(TOKEN_IV,
                    Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
        }
        if (!editor.commit()) {
            throw new IllegalStateException("Could not persist sync settings");
        }
    }

    public static String endpoint(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .getString(ENDPOINT, "");
    }

    public static boolean hasToken(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .contains(TOKEN_CIPHERTEXT);
    }

    public static void clearToken(Context context) {
        if (!context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit().remove(TOKEN_CIPHERTEXT).remove(TOKEN_IV).commit()) {
            throw new IllegalStateException("Could not clear sync credential");
        }
    }

    public static String token(Context context) throws Exception {
        SharedPreferences preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
        String ciphertext = preferences.getString(TOKEN_CIPHERTEXT, "");
        String initializationVector = preferences.getString(TOKEN_IV, "");
        if (ciphertext.isEmpty() || initializationVector.isEmpty()) {
            return "";
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateKey(),
                new GCMParameterSpec(128, Base64.decode(initializationVector, Base64.NO_WRAP)));
        cipher.updateAAD(endpoint(context).getBytes(StandardCharsets.UTF_8));
        return new String(
                cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP)),
                StandardCharsets.UTF_8);
    }

    public static boolean isValidToken(String token) {
        if (token == null
                || token.length() < MIN_TOKEN_LENGTH
                || token.length() > MAX_TOKEN_LENGTH) {
            return false;
        }
        for (int index = 0; index < token.length(); index++) {
            char character = token.charAt(index);
            boolean urlSafeAscii = (character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '_'
                    || character == '-';
            if (!urlSafeAscii) {
                return false;
            }
        }
        return true;
    }

    private static SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }
}
