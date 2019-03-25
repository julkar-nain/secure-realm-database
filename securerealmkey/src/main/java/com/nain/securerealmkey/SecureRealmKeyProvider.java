package com.nain.securerealmkey;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import java.security.SecureRandom;

/**
 * This Class provides secure realm key
 * The secure realm key will be stored in android shared preferences with encryption
 *
 * @author julkar nain
 * @since 3/25/19
 */
public class SecureRealmKeyProvider {

    private static final String REALM_ENCRYPTION_KEY = "realm_encryption_key";
    private static final String PREFERENCES_KEY = "secure_development_preferences";
    private EncryptionProvider encryptionProvider;
    private Context context;

    public SecureRealmKeyProvider(Context context) {
        this.context = context;
        encryptionProvider = new EncryptionProvider(context);
    }

    public SecureRealmKeyProvider(Context context, String alias) {
        encryptionProvider = new EncryptionProvider(context, alias);
    }

    /**
     * This method provide secure encryption key
     *
     * @return key
     */
    public byte[] getSecureRealmKey() {
        String key = getSharedPreference().getString(REALM_ENCRYPTION_KEY, null);

        if (TextUtils.isEmpty(key)) {
            return createRealmKey(context);
        }

        return encryptionProvider.decrypt(key);
    }

    private void setRealmKey(byte[] key) {
        SharedPreferences.Editor editor = getSharedPreference().edit();
        editor.putString(REALM_ENCRYPTION_KEY, encryptionProvider.encrypt(key));
        editor.apply();
    }

    private byte[] createRealmKey(Context context) {
        byte[] key = new byte[64];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        setRealmKey(key);

        return key;
    }

    private SharedPreferences getSharedPreference() {
        return context.getSharedPreferences(PREFERENCES_KEY, Context.MODE_PRIVATE);
    }
}