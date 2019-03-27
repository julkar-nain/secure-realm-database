package com.nain.securerealmdb.encryption;

/**
 * @author julkar nain
 * @since 3/27/19
 */
public interface NonReversibleData {
    String getSalt();
    String getEncryptedData();
    void setSalt(String salt);
    void setEncryptedData(String encryptedData);
}
