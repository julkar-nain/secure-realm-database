package com.nain.securerealmdb.encryptionhelper;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import java.security.SecureRandom;

/**
 * This Class provides secure key
 * The secure key will be stored in android shared preferences with encryption
 *
 * @author julkar nain
 * @since 3/25/19
 */
public class SecureKeyProvider {

    private static final String PREFERENCES_KEY = "secure_preferences";
    private KeystoreKeyProvider encryptionProvider;
    private Context context;

    public SecureKeyProvider(Context context) {
        this.context = context;
        encryptionProvider = new KeystoreKeyProvider(context);
    }

    public SecureKeyProvider(Context context, String alias) {
        this.context = context;
        encryptionProvider = new KeystoreKeyProvider(context, alias);
    }

    /**
     * This method provide secure encryption key
     *
     * @param keySize
     * @param preferencesKey
     *
     * @return key
     */
    public byte[] getSecureKey(int keySize, String preferencesKey) {
        String key = getSharedPreference().getString(preferencesKey, null);

        if (TextUtils.isEmpty(key)) {
            return createSecureKey(keySize, preferencesKey);
        }

        return encryptionProvider.decrypt(key);
    }

    private void saveSecureKey(byte[] key, String preferencesKey) {
        SharedPreferences.Editor editor = getSharedPreference().edit();
        editor.putString(preferencesKey, encryptionProvider.encrypt(key));
        editor.apply();
    }

    private byte[] createSecureKey(int keySize, String preferencesKey) {
        byte[] key = new byte[keySize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        saveSecureKey(key, preferencesKey);

        return key;
    }

    private SharedPreferences getSharedPreference() {
        return context.getSharedPreferences(PREFERENCES_KEY, Context.MODE_PRIVATE);
    }
}
