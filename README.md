Secure Realm Database for android
=================================
This is an android library that helps you to ensure data security of realm database in android device. Initially the library is focused on realm database only but this idea can be used for any other database. [This article](https://dzone.com/articles/secure-realm-encryption-key-for-android-applicatio)  demostrates the library in more easier way
## Feature
This Library helps to secure your realm database for android device. It provides the following features :

- It generates encryption key automatically for encrypting realm database.
- It can encrypt any specific data that is stored in database.
- It ensures data security by non reversible encryption.

## Dependency
Step 1. Add the JitPack repository to your build file
Add it in your root build.gradle at the end of repositories:

	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}

Step 2. Add the dependency

	dependencies {
	        implementation 'com.github.julkar-nain:secure-realm-database:v1.0-alpha'
	}
  
## Usage
Realm database provides default encryption feature for encrypting whole database. In this case you have to provide a encryption key. This library generates a encryption key for you and stored in the device securely.
    
    private RealmConfiguration initializeRealmConfig() {
        RealmEncryptionKeyProvider realmEncryptionKeyProvider = new RealmEncryptionKeyProvider(this);
        byte[] encryptionKey = realmEncryptionKeyProvider.getSecureRealmKey();

        return new RealmConfiguration.Builder()
                .schemaVersion(REALM_VERSION)
                .encryptionKey(encryptionKey)
                .build();
    }
    
You can upload the encryption key to remote source to restore the key incase device lost it in any situation. This library makes it easy for you.

    //This formatted key can be uploded to remote key
    String formattedKey = RealmEncryptionKeyProvider.Util.getFormattedSecureKey(encryptionKey);
    
    String encryptionKey = RealmEncryptionKeyProvider.Util.getSecureKey(formattedKey);
    
    
You can encrypt any specific data and store that in database if you don't want to encrypt whole database. 

    String encyptedText = encryptionProvider.getEncryptedText(plainText);

    String plainTextAgian = encryptionProvider.getPlainText(encyptedText);
    
    
The library can ensure your data security for realm database. You can use non reversible encryption for storing password, pin or any other sensitive data that shouldn't be revealed.

        String userName = "user name";
        String passwrod = "password";

        User userToBeStored = new User();
        userToBeStored.setUserName(userName);
        userToBeStored = (User) NonReversibleEncryptionProvider.prepareData(passwrod, userToBeStored);
        //this userToBeStored object can be stored in local realm db

        //Now match the stored data with new entered data

        //enterd data
        String enteredUserName = "user name";
        String enteredPassword = "password1";
        User existingUser = userToBeStored; //this can be retrieve from local db

        if (NonReversibleEncryptionProvider.isMatchedData(enteredPassword, existingUser)){
            Log.d(TAG, "matched with the existing");
        }else {
            Log.d(TAG, "not matched with the existing");
        }
        

### Licence         
Apache License, Version 2.0

    Copyright (C) 2019, Julkar Nain

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
   
        http://www.apache.org/licenses/LICENSE-2.0
     
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
        
        
