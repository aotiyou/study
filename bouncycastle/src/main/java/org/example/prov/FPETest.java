package org.example.prov;

import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import org.bouncycastle.jcajce.spec.FPEParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @auther: infosec
 * @date: 2026/1/30
 * @description: org.example.prov
 * @version: 1.0
 */
public class FPETest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void test() throws Exception {
        FPEParameterSpec parameterSpec = new FPEParameterSpec(100, new byte[0]);
        SecretKey aesKey = new SecretKeySpec(new byte[32], "AES");

        Cipher multipleOperationsCipher = Cipher.getInstance("AES/FF1/NoPadding", "BC");
        multipleOperationsCipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);

        Cipher singleOperationCipher = Cipher.getInstance("AES/FF1/NoPadding", "BC");
        singleOperationCipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);

        byte[] ciphertext1 = multipleOperationsCipher.doFinal("123".getBytes());

        byte[] ciphertext2 = singleOperationCipher.doFinal("123".getBytes());

        assertTrue(Arrays.areEqual(ciphertext1, ciphertext2));
    }


    @Test
    public void testFPEChar() throws Exception {
        FPECharEncryptor fpeEnc = new FPECharEncryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), "0123456789".toCharArray());

        String s1 = "01234567890123456";
        char[] encrypted = fpeEnc.process(s1.toCharArray());

        FPECharDecryptor fpeDec = new FPECharDecryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), "0123456789".toCharArray());
        char[] decrypted = fpeDec.process(encrypted);

        assertEquals(s1, new String(decrypted));

        String bigAlpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "\u0400\u0401\u0402\u0403\u0404\u0405\u0406\u0407\u0408\u0409\u040a\u040b\u040c\u040d\u040e\u040f"
                + "\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f"
                + "\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042a\u042b\u042c\u042d\u042e\u042f"
                + "\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f"
                + "\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044a\u044b\u044c\u044d\u044e\u044f"
                + "\u0450\u0451\u0452\u0453\u0454\u0455\u0456\u0457\u0458\u0459\u045a\u045b\u045c\u045d\u045e\u045f"
                + "\u0210\u0211\u0212\u0213\u0214\u0215\u0216\u0217\u0218\u0219\u021a\u021b\u021c\u021d\u021e\u021f"
                + "\u0220\u0221\u0222\u0223\u0224\u0225\u0226\u0227\u0228\u0229\u022a\u022b\u022c\u022d\u022e\u022f"
                + "\u0230\u0231\u0232\u0233\u0234\u0235\u0236\u0237\u0238\u0239\u023a\u023b\u023c\u023d\u023e\u023f"
                + "\u0240\u0241\u0242\u0243\u0244\u0245\u0246\u0247\u0248\u0249\u024a\u024b\u024c\u024d\u024e\u024f"
                + "\u2210\u2211\u2212\u2213\u2214\u2215\u2216\u2217\u2218\u2219\u221a\u221b\u221c\u221d\u221e\u221f"
                + "\u2220\u2221\u2222\u2223\u2224\u2225\u2226\u2227\u2228\u2229\u222a\u222b\u222c\u222d\u222e\u222f"
                + "\u2230\u2231\u2232\u2233\u2234\u2235\u2236\u2237\u2238\u2239\u223a\u223b\u223c\u223d\u223e\u223f"
                + "\u2240\u2241\u2242\u2243\u2244\u2245\u2246\u2247\u2248\u2249\u224a\u224b\u224c\u224d\u224e\u224f";

        fpeEnc = new FPECharEncryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), bigAlpha.toCharArray());

        s1 = "01234567890123456\u0222\u0223\u0224\u0225\u0226abcdefg\u224f";

        encrypted = fpeEnc.process(s1.toCharArray());

        fpeDec = new FPECharDecryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), bigAlpha.toCharArray());
        decrypted = fpeDec.process(encrypted);

        assertEquals(s1, new String(decrypted));
    }


    public static class FPECharEncryptor
    {
        private Cipher cipher;
        private AlphabetMapper alphabetMapper;

        public FPECharEncryptor(SecretKey key, char[] alphabet)
                throws GeneralSecurityException
        {
            this(key, new byte[0], alphabet);
        }

        public FPECharEncryptor(SecretKey key, byte[] tweak, char[] alphabet)
                throws GeneralSecurityException
        {
            alphabetMapper = new BasicAlphabetMapper(alphabet);
            cipher = Cipher.getInstance(key.getAlgorithm() + "/FF1/NoPadding", "BC");

            cipher.init(Cipher.ENCRYPT_MODE, key, new FPEParameterSpec(alphabet.length, tweak));
        }

        public char[] process(char[] input)
                throws GeneralSecurityException
        {
            byte[] encData = cipher.doFinal(alphabetMapper.convertToIndexes(input));

            return alphabetMapper.convertToChars(encData);
        }
    }

    public static class FPECharDecryptor
    {
        private Cipher cipher;
        private AlphabetMapper alphabetMapper;

        public FPECharDecryptor(SecretKey key, char[] alphabet)
                throws GeneralSecurityException
        {
            this(key, new byte[0], alphabet);
        }

        public FPECharDecryptor(SecretKey key, byte[] tweak, char[] alphabet)
                throws GeneralSecurityException
        {
            alphabetMapper = new BasicAlphabetMapper(alphabet);
            cipher = Cipher.getInstance(key.getAlgorithm() + "/FF1/NoPadding", "BC");

            cipher.init(Cipher.DECRYPT_MODE, key, new FPEParameterSpec(alphabet.length, tweak));
        }

        public char[] process(char[] input)
                throws GeneralSecurityException
        {
            byte[] encData = cipher.doFinal(alphabetMapper.convertToIndexes(input));

            return alphabetMapper.convertToChars(encData);
        }
    }

}
