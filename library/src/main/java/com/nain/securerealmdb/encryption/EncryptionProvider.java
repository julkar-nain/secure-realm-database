package com.nain.securerealmdb.encryption;

import android.content.Context;
import android.util.Base64;

import com.nain.securerealmdb.key.SecureKeyProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author julkar nain
 * @since 3/27/19
 */
public class EncryptionProvider {

    private static final String SECURE_DATA_KEY_PREFERENCE = "secure_data_key_preference";
    private static final String ALGORITHM_NAME = "AES";
    private static final int KEY_SIZE = 128; //128 bits or 16 bytes

    private SecureKeyProvider secureKeyProvider;


    public EncryptionProvider(Context context) {
        secureKeyProvider = new SecureKeyProvider(context);
    }

    public EncryptionProvider(Context context, String alias) {
        secureKeyProvider = new SecureKeyProvider(context, alias);
    }

    public String getEncryptedText(String plainText) throws Exception {
        return encrypt(plainText);
    }

    public String getPlainText(String encryptedText) throws Exception {
        return deCncrypt(encryptedText);
    }

    public String getEncryptedInt(int plainInt) throws Exception {
        return encrypt(plainInt + "");
    }

    public int getPlainInt(String encryptedInt) throws Exception {
        return Integer.parseInt(deCncrypt(encryptedInt));
    }

    public String getEncryptedLong(long plainLong) throws Exception {
        return encrypt(plainLong + "");
    }

    public long getPlainLong(String encryptedLong) throws Exception {
        return Long.parseLong(deCncrypt(encryptedLong));
    }

    public String getEncryptedDouble(double plainDouble) throws Exception {
        return encrypt(plainDouble + "");
    }

    public double getPlainDouble(String encryptedDouble) throws Exception {
        return Double.parseDouble(deCncrypt(encryptedDouble));
    }

    public String getEncryptedBoolean(boolean plainBoolean) throws Exception {
        return encrypt(plainBoolean ? "true" : "false");
    }

    public boolean getPlainBoolean(String encryptedBoolean) throws Exception {
        return Boolean.parseBoolean(deCncrypt(encryptedBoolean));
    }

    private String encrypt(String plainData) throws Exception {
        return Base64.encodeToString(getCipherInstance(Cipher.ENCRYPT_MODE)
                .doFinal(plainData.getBytes()), Base64.NO_WRAP);
    }

    private String deCncrypt(String encryptedData) throws Exception {
        return new String(getCipherInstance(Cipher.DECRYPT_MODE).
                doFinal(Base64.decode(encryptedData, Base64.NO_WRAP)));
    }

    private Cipher getCipherInstance(int cipherMode) throws Exception {
        byte[] key = secureKeyProvider.getSecureKey(KEY_SIZE, SECURE_DATA_KEY_PREFERENCE);
        SecretKeySpec skeySpec = new SecretKeySpec(key, 0, key.length, ALGORITHM_NAME);
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
        cipher.init(cipherMode, skeySpec);

        return cipher;
    }
}
