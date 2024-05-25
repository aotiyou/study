package cn.com.infosec.crypto.algithm;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author infosec
 * @since 2024/5/22
 */
public class AesMain {

    @Test
    public void testECB() throws Exception {
        //原文
        String message = "Hello, world!";
        System.out.println("Message: " + message);

        // 128位密钥= 16 bytes Key
        byte[] key = "1234567890abcdef".getBytes("UTF-8");

        //加密
        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = encryptECB(key, data);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypt));

        //解密
        byte[] decrypt = decryptECB(key, encrypt);
        System.out.println("Decrypted: " + new String(decrypt, StandardCharsets.UTF_8));
    }

    @Test
    public void testCBC() throws Exception {
        // 原文
        String message = "Hello, world!";
        System.out.println("Message: " + message);

        // 256位密钥 = 32 bytes Key
        byte[] key = "1234567890abcdef1234567890abcdef".getBytes("UTF-8");

        // 加密
        byte[] encrypted = encryptCBC(key, message.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        // 解密
        byte[] decrypted = decryptCBC(key, encrypted);
        System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));

    }

    /**
     * ECB加密
     * @author infosec
     * @since  2024/5/22
     * @param key
     * @param input
     * @return byte[]
     */
    public byte[] encryptECB(byte[] key, byte[] input) throws Exception {
        // 1.根据算法名称/工作模式/填充模式获取Cipher实例
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // 2.根据算法名称初始化一个SecretKey实例，密钥必须是指定长度
        SecretKey keySpec = new SecretKeySpec(key, "AES");
        // 3.使用SecretKey初始化Cipher实例，并设置加密或解密模式
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        // 4.传入明文，获得密文
        return cipher.doFinal(input);
    }

    /**
     * ECB解密
     *
     * @author infosec
     * @since  2024/5/22
     * @param key
     * @param input
     * @return byte[]
     */
    public byte[] decryptECB(byte[] key, byte[] input) throws Exception {
        // 1.根据算法名称/工作模式/填充模式获取Cipher实例
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // 2.根据算法名称初始化一个SecretKey实例，密钥必须是指定长度
        SecretKey keySpec = new SecretKeySpec(key, "AES");
        // 3.使用SecretKey初始化Cipher实例，并设置加密或解密模式
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        // 4.传入密文，获得明文
        return cipher.doFinal(input);
    }

    /**
     * CBC加密
     * @author infosec
     * @since  2024/5/22
     * @param key
     * @param input
     * @return byte[]
     */
    public byte[] encryptCBC(byte[] key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey keySpec = new SecretKeySpec(key, "AES");

        // CBC模式需要生成一个16 bytes的initialization vector：
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] iv = sr.generateSeed(16);
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivps);
        byte[] data = cipher.doFinal(input);

        // IV不需要保密，把IV和密文一起返回
        return join(iv, data);
    }

    public byte[] decryptCBC(byte[] key, byte[] input) throws Exception {
        // 把input分割成IV和密文
        byte[] iv = new byte[16];
        byte[] data = new byte[input.length - 16];
        System.arraycopy(input, 0, iv, 0, 16);
        System.arraycopy(input, 16, data, 0, data.length);

        // 解密
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivps);
        return cipher.doFinal(data);
    }
    public byte[] join(byte[] bs1, byte[] bs2) {
        byte[] r = new byte[bs1.length + bs2.length];
        System.arraycopy(bs1, 0, r, 0, bs1.length);
        System.arraycopy(bs2, 0, r, bs1.length, bs2.length);
        return r;
    }


}
