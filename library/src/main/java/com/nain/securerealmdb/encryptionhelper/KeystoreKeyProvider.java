package com.nain.securerealmdb.encryptionhelper;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import static java.security.spec.RSAKeyGenParameterSpec.F4;

/**
 * This Class provides secure key based on android key story
 * This Class provides String encryption as well
 *
 * @author julkar nain
 * @since 12/20/18
 */
public class KeystoreKeyProvider {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ALGORITHOM_TYPE = "RSA";
    private static final String PADDING_TYPE = "PKCS1Padding";
    private static final String DEFAULT_ALIAS = "default_alias";
    private Context context;
    private String alias;


    public KeystoreKeyProvider(Context context) {
        this.context = context;
        this.alias = DEFAULT_ALIAS;
    }

    public KeystoreKeyProvider(Context context, String keyAlias) {
        this.context = context;
        this.alias = keyAlias;
    }

    /**
     * This method check secure key available or not
     *
     * @return true or false value
     */
    public boolean isSecureKeyAvailable() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            return keyStore.containsAlias(alias);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * This method provides secure key
     *
     * @return byte array of secured key
     */
    public byte[] getSecureKey() {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = getSecretKey(alias);

            if (privateKeyEntry == null) {
                Log.d("key", "key not found");

                return null;
            }
            Certificate cert = privateKeyEntry.getCertificate();

            if (cert == null) {
                Log.d("key", "certificate not found");

                return null;
            }

            return cert.getEncoded();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method encrypt plain text
     *
     * @param plainText (String)
     * @return encrypted text
     */
    public String encrypt(String plainText) {
        return encrypt(plainText.getBytes());
    }

    /**
     * This method encrypt plain text
     *
     * @param bytes (byte array of plain text)
     * @return encrypted text
     */
    public String encrypt(byte[] bytes) {
        if (!isSecureKeyAvailable()) {
            createSecretKeys();
        }

        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(alias));
            return Base64.encodeToString(cipher.doFinal(bytes), Base64.NO_WRAP);
        } catch (NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * This method encrypt plain text
     *
     * @param encryptedText (String)
     * @return plain text
     */
    public byte[] decrypt(String encryptedText) {
        if (!isSecureKeyAvailable()) {
            return null;
        }

        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(alias));
            return cipher.doFinal(Base64.decode(encryptedText, Base64.NO_WRAP));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void createSecretKeys() {
        if (!isSecureKeyAvailable()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                createSecretKeysForM();
            } else {
                try {
                    createSecretKeysBelowM();
                } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void createSecretKeysBelowM() throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 100);

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal(alias))
                .setSerialNumber(BigInteger.valueOf(Math.abs(alias.hashCode())))
                .setStartDate(start.getTime()).setEndDate(end.getTime())
                .setKeySize(512)
                .build();

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(ALGORITHOM_TYPE, ANDROID_KEYSTORE);
        kpGenerator.initialize(spec);
        kpGenerator.generateKeyPair();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void createSecretKeysForM() {
        try {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(1024, F4))
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512)
                    .setUserAuthenticationRequired(false)
                    .build();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
            keyPairGenerator.initialize(spec);
            keyPairGenerator.generateKeyPair();

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private KeyStore.PrivateKeyEntry getSecretKey(String alias) {
        if (!isSecureKeyAvailable()) {
            createSecretKeys();
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            KeyStore.Entry keyStoreEntry = keyStore.getEntry(alias, null);
            return keyStoreEntry instanceof KeyStore.PrivateKeyEntry ? (KeyStore.PrivateKeyEntry) keyStoreEntry : null;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private PrivateKey getPrivateKey(String alias) {
        return getSecretKey(alias).getPrivateKey();
    }

    private PublicKey getPublicKey(String alias) {
        return getSecretKey(alias).getCertificate().getPublicKey();
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(String.format("%s/%s/%s", ALGORITHOM_TYPE, "NONE", PADDING_TYPE));
    }
}