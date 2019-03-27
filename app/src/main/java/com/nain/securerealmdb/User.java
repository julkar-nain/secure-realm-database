package com.nain.securerealmdb;

import com.nain.securerealmdb.encryption.NonReversibleData;

/**
 * @author julkar nain
 * @since 3/27/19
 */
public class User implements NonReversibleData {

    private String userName;
    private String password;
    private String salt;

    @Override
    public String getSalt() {
        return salt;
    }

    @Override
    public String getEncryptedData() {
        return password;
    }

    @Override
    public void setSalt(String salt) {
        this.salt = salt;
    }

    @Override
    public void setEncryptedData(String encryptedData) {
        password = encryptedData;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }
}
