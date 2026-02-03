package org.example.prov;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.util.Base64;

public class AESGCMExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 生成AES密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        // 初始化参数
        byte[] iv = new byte[12]; // 推荐12字节
        int tagLength = 128;
        GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, iv);

        // 加密
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] plaintext = "Hello, BC GCM!".getBytes();
        byte[] ciphertext = encryptCipher.doFinal(plaintext);

        System.out.println("Base64(ciphertext+tag): " + Base64.getEncoder().encodeToString(ciphertext));

        // 解密
        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        byte[] decrypted = decryptCipher.doFinal(ciphertext);
        System.out.println("解密结果: " + new String(decrypted));
    }
}
