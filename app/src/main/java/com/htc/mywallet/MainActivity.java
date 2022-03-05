package com.htc.mywallet;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import wallet.core.jni.CoinType;
import wallet.core.jni.HDWallet;
import wallet.core.jni.PrivateKey;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "HDKey";
    Button Btn_CreateHDKey, Btn_StoreHDKey, Btn_LoadHDKey;
    TextView TV;
    HDWallet MyWallet;
    private static final int AUTHENTICATION_DURATION_SECONDS = 30;
    private static final int DEFAULT_KEY_STRENGTH = 128;
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_STORE_FILENAME = "hdkey";
    Context context;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        context = this;
        Btn_CreateHDKey = findViewById(R.id.CreateHDKey);
        Btn_CreateHDKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                CreateHDKey();
            }
        });
        Btn_StoreHDKey = findViewById(R.id.StoreHDKey);
        Btn_StoreHDKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StoreHDKey();
            }
        });
        Btn_LoadHDKey = findViewById(R.id.LoadHDKey);
        Btn_LoadHDKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                LoadHDKey();
            }
        });
        TV = findViewById(R.id.TV);

        System.loadLibrary("TrustWalletCore");
    }

    private void CreateHDKey() {
        MyWallet = new HDWallet(DEFAULT_KEY_STRENGTH, "");
        TV.setText(MyWallet.mnemonic());
    }

    private void StoreHDKey() {

        if (MyWallet != null) {
            PrivateKey pk = MyWallet.getKeyForCoin(CoinType.ETHEREUM);
            byte[] data = MyWallet.mnemonic().getBytes();
            KeyStore keyStore = null;
            String fileName = KEY_STORE_FILENAME;

            try {
                keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
                keyStore.load(null);

                /* KEY GENERATION */
                // Define the key spec
                KeyGenParameterSpec aesSpec = new KeyGenParameterSpec.Builder(
                        fileName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setKeySize(256)
                        .setIsStrongBoxBacked(false)
                        .setInvalidatedByBiometricEnrollment(false)
                        .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
                        .setRandomizedEncryptionRequired(true)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();

                KeyGenerator keyGenerator = null;
                keyGenerator = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        ANDROID_KEY_STORE);
                keyGenerator.init(aesSpec);

                final SecretKey secretKey = keyGenerator.generateKey();
                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] iv = cipher.getIV();
                String ivPath = getFilePath(context, fileName + "iv");
                boolean success = writeBytesToFile(ivPath, iv);
                if (!success)
                {
                    Log.d(TAG, "Failed to create the iv file for: " + fileName + "iv");
                    TV.setText("Failed to create the iv file for: " + fileName + "iv");
                    return;
                }

                String encryptedHDKeyPath = getFilePath(context, fileName);
                try (CipherOutputStream cipherOutputStream = new CipherOutputStream(
                        new FileOutputStream(encryptedHDKeyPath),
                        cipher))
                {
                    cipherOutputStream.write(data);
                }
                catch (Exception ex)
                {
                    Log.d(TAG,"Failed to create the file for: " + fileName);
                    TV.setText("Failed to create the file for: " + fileName);
                    return;
                }
            }
            catch (Exception ex) {
                deleteKey(fileName);
            }
            TV.setText("HDKey " + fileName + " stored");
        }
    }

    private void LoadHDKey() {
        String fileName = KEY_STORE_FILENAME;

        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            String matchingAddr = findMatchingAddrInKeyStore(fileName);
            if (!keyStore.containsAlias(matchingAddr))
            {
                TV.setText("Key not found in keystore. Re-import key.");
                return;
            }

            //create a stream to the encrypted bytes
            FileInputStream encryptedHDKeyBytes = new FileInputStream(getFilePath(context, matchingAddr));
            SecretKey secretKey = (SecretKey) keyStore.getKey(matchingAddr, null);
            boolean ivExists = new File(getFilePath(context, matchingAddr + "iv")).exists();
            byte[] iv = null;

            if (ivExists)
                iv = readBytesFromFile(getFilePath(context, matchingAddr + "iv"));
            if (iv == null || iv.length == 0)
            {
                TV.setText("cannot_read_encrypt_file");
                return;
            }
            Cipher outCipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            outCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            CipherInputStream cipherInputStream = new CipherInputStream(encryptedHDKeyBytes, outCipher);
            byte[] mnemonicBytes = readBytesFromStream(cipherInputStream);

            String mnemonic = new String(mnemonicBytes);
            MyWallet = new HDWallet(mnemonic, "");

            TV.setText(mnemonic);
        }
        catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e )
        {
            e.printStackTrace();
            TV.setText(e.getMessage());
        }
        catch (Exception e)
        {
            TV.setText(e.getMessage());
        }
    }


    synchronized static String getFilePath(Context context, String fileName)
    {
        //check for matching file
        File check = new File(context.getFilesDir(), fileName);
        if (check.exists())
        {
            return check.getAbsolutePath(); //quick return
        }
        else
        {
            //find matching file, ignoring case
            File[] files = context.getFilesDir().listFiles();
            for (File checkFile : files)
            {
                if (checkFile.getName().equalsIgnoreCase(fileName))
                {
                    return checkFile.getAbsolutePath();
                }
            }
        }
        return check.getAbsolutePath(); //Should never get here
    }

    private String findMatchingAddrInKeyStore(String keyAddress)
    {
        try
        {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            Enumeration<String> keys = keyStore.aliases();

            while (keys.hasMoreElements())
            {
                String thisKey = keys.nextElement();
                if (keyAddress.equalsIgnoreCase(thisKey))
                {
                    return thisKey;
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return keyAddress;
    }

    static byte[] readBytesFromStream(InputStream in)
    {
        // this dynamically extends to take the bytes you read
        ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();
        // this is storage overwritten on each iteration with bytes
        int bufferSize = 1024;
        byte[] buffer = new byte[bufferSize];
        // we need to know how may bytes were read to write them to the byteBuffer
        int len;
        try
        {
            while ((len = in.read(buffer)) != -1)
            {
                byteBuffer.write(buffer, 0, len);
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                byteBuffer.close();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            if (in != null)
            {
                try
                {
                    in.close();
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                }
            }
        }
        // and then we can return your byte array.
        return byteBuffer.toByteArray();
    }

    static byte[] readBytesFromFile(String path)
    {
        byte[] bytes = null;
        FileInputStream fin;
        try
        {
            File file = new File(path);
            fin = new FileInputStream(file);
            bytes = readBytesFromStream(fin);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        return bytes;
    }

    private boolean writeBytesToFile(String path, byte[] data)
    {
        FileOutputStream fos = null;
        try
        {
            File file = new File(path);
            fos = new FileOutputStream(file);
            // Writes bytes from the specified byte array to this file output stream
            fos.write(data);
            return true;
        }
        catch (FileNotFoundException e)
        {
            Log.d(TAG, "File not found" + e);
        }
        catch (IOException ioe)
        {
            Log.d(TAG, "Exception while writing file");
        }
        finally
        {
            // close the streams using close method
            try
            {
                if (fos != null)
                {
                    fos.close();
                }
            }
            catch (IOException ioe)
            {
                Log.d(TAG, "Error while closing stream: " + ioe);
            }
        }
        return false;
    }

    synchronized void deleteKey(String keyAddress)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            String matchingAddr = findMatchingAddrInKeyStore(keyAddress);
            if (keyStore.containsAlias(matchingAddr)) keyStore.deleteEntry(matchingAddr);
            File encryptedKeyBytes = new File(getFilePath(context, matchingAddr));
            File encryptedBytesFileIV = new File(getFilePath(context, matchingAddr + "iv"));
            if (encryptedKeyBytes.exists()) encryptedKeyBytes.delete();
            if (encryptedBytesFileIV.exists()) encryptedBytesFileIV.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}