package com.nain.securerealmdb.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.nain.securerealmdb.Utils.decodeHexString;
import static com.nain.securerealmdb.Utils.encodeHexString;

/**
 * This class provides non reversible encryption
 * Non reversible encryption can be on password, pin or any other credential data
 *
 * @author julkar nain
 * @since 12/20/18
 */

public class NonReversibleEncryptionProvider {

    /**
     * This method match input data with existing data
     *
     * @param plainData
     * @param data
     *
     * @return boolean true if matched
     * **/
    public static boolean isMatchedData(String plainData, NonReversibleData data) {
        return Arrays.equals(encryp(plainData.getBytes(), decodeHexString(data.getSalt())),
                decodeHexString(data.getEncryptedData()));
    }

    /**
     * This method prepare Non Reversible Data to store
     *
     * @param plainPin
     * @param data
     *
     * @return NonReversibleData this will be stored
     * **/
    public static NonReversibleData prepareData(String plainPin, NonReversibleData data) {
        byte[] salt = createRandomSalt(32);
        data.setSalt(encodeHexString(salt));
        data.setEncryptedData(encodeHexString(encryp(plainPin.getBytes(), salt)));

        return data;
    }

    private static byte[] encryp(byte [] plainData, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");

            messageDigest.update(salt);
            return messageDigest.digest(plainData);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static byte[] createRandomSalt(int saltSize) {
        byte[] salt = new byte[saltSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);

        return salt;
    }
}