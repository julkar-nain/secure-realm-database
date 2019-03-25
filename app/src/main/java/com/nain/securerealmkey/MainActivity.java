package com.nain.securerealmkey;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import io.realm.Realm;
import io.realm.RealmConfiguration;

public class MainActivity extends AppCompatActivity {

    private static final int REALM_VERSION = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Realm.init(this);
        Realm.setDefaultConfiguration(initializeRealmConfig());
    }

    private RealmConfiguration initializeRealmConfig() {
        SecureRealmKeyProvider secureRealmKeyProvider = new SecureRealmKeyProvider(this);
        byte[] encryptionKey = secureRealmKeyProvider.getSecureRealmKey();

        return new RealmConfiguration.Builder()
                .schemaVersion(REALM_VERSION)
                .encryptionKey(encryptionKey)
                .build();
    }
}
