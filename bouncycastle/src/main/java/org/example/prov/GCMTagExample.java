package org.example.prov;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

public class GCMTagExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        byte[] iv = new byte[12];
        int tagLenBits = 128;
        GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLenBits, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] plaintext = "TestData12345".getBytes();
        byte[] encrypted = cipher.doFinal(plaintext);

        int tagLenBytes = tagLenBits / 8;
        byte[] cipherPart = Arrays.copyOfRange(encrypted, 0, encrypted.length - tagLenBytes);
        byte[] tagPart = Arrays.copyOfRange(encrypted, encrypted.length - tagLenBytes, encrypted.length);

        System.out.println("Cipher(Hex): " + HexFormat.of().formatHex(cipherPart));
        System.out.println("Tag(Hex): " + HexFormat.of().formatHex(tagPart));
        System.out.println("Cipher+Tag(Hex): " + HexFormat.of().formatHex(encrypted));
    }
}
