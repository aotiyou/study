package org.example.prov;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author infosec
 * @since 2025/11/6
 */
public class SymmetricTest {

    @Test
    public void test() throws Exception {
        byte[] plain = "1".getBytes();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", new BouncyCastleProvider());
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] update = cipher.update(plain);
        byte[] update1 = cipher.update(plain);
        byte[] cipherBytes = cipher.doFinal(plain);

        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipher.update(cipherBytes);
        plain = cipher.doFinal();

        System.out.println("plain = " + new String(plain));
    }

    @Test
    public void test1() {
        byte[] a = new byte[1];
        byte[] b = new byte[2];

    }

}
