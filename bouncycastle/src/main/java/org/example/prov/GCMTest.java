package org.example.prov;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

/**
 * @author infosec
 * @since 2025/10/11
 */
public class GCMTest {

    @Test
    public void test() throws InvalidCipherTextException {
        byte[] key = new byte[16]; // AES-128
        byte[] iv = new byte[12];  // GCM 推荐使用 12 字节 IV
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        random.nextBytes(iv);

        String plaintext = "Hello, AES-GCM from BC!";
        byte[] ciphertext = encrypt(key, iv, plaintext.getBytes());
        byte[] decrypted = decrypt(key, iv, ciphertext);

        System.out.println("Key: " + Hex.toHexString(key));
        System.out.println("IV:  " + Hex.toHexString(iv));
        System.out.println("Ciphertext: " + Hex.toHexString(ciphertext));
        System.out.println("Decrypted: " + new String(decrypted));
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] data)
            throws InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv, null);
        cipher.init(true, params);

        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, output, 0);
        len += cipher.doFinal(output, len);
        return output;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] cipherText)
            throws InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv, null);
        cipher.init(false, params);

        byte[] output = new byte[cipher.getOutputSize(cipherText.length)];
        int len = cipher.processBytes(cipherText, 0, cipherText.length, output, 0);
        len += cipher.doFinal(output, len);
        return output;
    }

}
