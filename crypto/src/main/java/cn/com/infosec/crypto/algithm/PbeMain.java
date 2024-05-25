package cn.com.infosec.crypto.algithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2024/5/22
 */
public class PbeMain {

    @Test
    public void test() throws Exception {
        // 把BouncyCastle作为Provider添加到java.security
        Security.addProvider(new BouncyCastleProvider());
        // 原文
        String message = "Hello, world!";
        // 加密口令
        String password = "hello12345";
        // 16 bytes随机Salt
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        System.out.println(HexFormat.of().formatHex(salt));
        // 加密
        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = encrypt(password, salt, data);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypt));

        // 解密
        byte[] decrypt = decrypt(password, salt, encrypt);
        System.out.println("Decrypted: " + new String(decrypt, StandardCharsets.UTF_8));

    }

    public byte[] encrypt(String password, byte[] salt, byte[] input) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory skeyFactory = SecretKeyFactory.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        SecretKey skey = skeyFactory.generateSecret(keySpec);
        PBEParameterSpec pbeps = new PBEParameterSpec(salt, 1000);
        Cipher cipher = Cipher.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        cipher.init(Cipher.ENCRYPT_MODE, skey, pbeps);
        return cipher.doFinal(input);
    }

    public byte[] decrypt(String password, byte[] salt, byte[] input) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory skeyFactory = SecretKeyFactory.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        SecretKey skey = skeyFactory.generateSecret(keySpec);
        PBEParameterSpec pbeps = new PBEParameterSpec(salt, 1000);
        Cipher cipher = Cipher.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        cipher.init(Cipher.DECRYPT_MODE, skey, pbeps);
        return cipher.doFinal(input);

    }

}
