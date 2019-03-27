package com.nain.securerealmdb;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.nain.securerealmdb.encryption.EncryptionProvider;
import com.nain.securerealmdb.encryption.NonReversibleEncryptionProvider;
import com.nain.securerealmdb.key.RealmEncryptionKeyProvider;

import io.realm.Realm;
import io.realm.RealmConfiguration;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final int REALM_VERSION = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Realm.init(this);
        Realm.setDefaultConfiguration(initializeRealmConfig());

        EncryptionProvider encryptionProvider = new EncryptionProvider(this);

        try {
            String plainText = "example data";
            /*
            * This encrypted data can be stored into realm database
            * This way should be used when encryption key is not provided to realm db
            * */
            String encyptedText = encryptionProvider.getEncryptedText(plainText); // not readable

            String plainTextAgian = encryptionProvider.getPlainText(encyptedText); // it returns  plain text again

        } catch (Exception e) {
            e.printStackTrace();
        }

        //example of storing a user into local db or cloud using non reversible encryption way
        //This process ensures data security
        //Nobody can retrieve original data
        String userName = "user name";
        String passwrod = "password";

        User userToBeStored = new User();
        userToBeStored.setUserName(userName);
        userToBeStored = (User) NonReversibleEncryptionProvider.prepareData(passwrod, userToBeStored);
        //this userToBeStored object can be stored in local db or cloud

        //Now match the stored data with new entered data

        //enterd data
        String enteredUserName = "user name";
        String enteredPassword = "password1";
        User existingUser = userToBeStored; //this can be retrieve from local db or server using userName


        if (NonReversibleEncryptionProvider.isMatchedData(enteredPassword, existingUser)){
            Log.d(TAG, "matched with the existing");
        }else {
            Log.d(TAG, "not matched with the existing");
        }
    }

    private RealmConfiguration initializeRealmConfig() {
        RealmEncryptionKeyProvider realmEncryptionKeyProvider = new RealmEncryptionKeyProvider(this);

        byte[] encryptionKey = realmEncryptionKeyProvider.getSecureRealmKey();

        return new RealmConfiguration.Builder()
                .schemaVersion(REALM_VERSION)
                .encryptionKey(encryptionKey)
                .build();
    }
}
