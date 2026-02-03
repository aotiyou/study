package org.example.prov;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import java.security.SecureRandom;

public class SM4GCMExample {

    public static void main(String[] args) throws Exception {
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        random.nextBytes(iv);

        String plaintext = "Hello, SM4-GCM!";
        byte[] cipherText = encrypt(key, iv, plaintext.getBytes());
        byte[] plain = decrypt(key, iv, cipherText);

        System.out.println("Key: " + Hex.toHexString(key));
        System.out.println("IV:  " + Hex.toHexString(iv));
        System.out.println("Ciphertext: " + Hex.toHexString(cipherText));
        System.out.println("Plaintext: " + new String(plain));
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv, null);
        cipher.init(true, params);

        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, output, 0);
        cipher.doFinal(output, len);
        return output;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv, null);
        cipher.init(false, params);

        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, output, 0);
        cipher.doFinal(output, len);
        return output;
    }
}
