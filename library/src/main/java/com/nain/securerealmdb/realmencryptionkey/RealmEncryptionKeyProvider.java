package com.nain.securerealmdb.realmencryptionkey;

import android.content.Context;

import com.nain.securerealmdb.encryptionhelper.SecureKeyProvider;

/**
 * This Class provides secure realm key
 * The secure realm key will be stored in android shared preferences with encryption
 *
 * @author julkar nain
 * @since 3/25/19
 */
public class RealmEncryptionKeyProvider {

    private static final String REALM_ENCRYPTION_KEY_PREFERENCE = "realm_encryption_key_preference";
    private static final int KEY_SIZE = 64;
    private SecureKeyProvider secureKeyProvider;

    public RealmEncryptionKeyProvider(Context context) {
        secureKeyProvider = new SecureKeyProvider(context);
    }

    public RealmEncryptionKeyProvider(Context context, String alias) {
        secureKeyProvider = new SecureKeyProvider(context, alias);
    }

    /**
     * This method provide secure encryption key
     *
     * @return key
     */
    public byte[] getSecureRealmKey() {
        return secureKeyProvider.getSecureKey(KEY_SIZE, REALM_ENCRYPTION_KEY_PREFERENCE);
    }
}