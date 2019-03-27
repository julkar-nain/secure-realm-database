package com.nain.securerealmdb.key;

import android.content.Context;

import static com.nain.securerealmdb.Utils.decodeHexString;
import static com.nain.securerealmdb.Utils.encodeHexString;

/**
 * This Class provides secure realm key
 * The secure realm key will be stored in android shared preferences with encryption
 *
 * @author julkar nain
 * @since 3/25/19
 */
public class RealmEncryptionKeyProvider {

    private static final String REALM_ENCRYPTION_KEY_PREFERENCE = "realm_encryption_key_preference";
    private static final int KEY_SIZE = 512; // 512 bits or 64 bytes
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

    public static class Util {

        /*
         * This method provides formatted secure key
         * This formatted key can be uploaded to server side
         *
         * @param encyptionKey
         *
         * @return formatted secure key
         * */
        public static String getFormattedSecureKey(byte[] encryptionKey) {
            return encodeHexString(encryptionKey);
        }

        /*
         * This method provides secure key from formatted key
         * The formatted key can be retrieve from server side
         * This secure key will be used when stored secure key is lost
         *
         * @param formattedSecureKey
         *
         * @return secure key
         * */
        public static byte[] getSecureKey(String formattedSecureKey) {
            return decodeHexString(formattedSecureKey);
        }

    }
}