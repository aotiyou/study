package cn.com.infosec.crypto.algithm;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2024/5/22
 */
public class CertificateMain {


    @Test
    public void test() throws Exception {
        // 原文
        String message = "hello world";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        // 读取KeyStore
        KeyStore ks = loadKeyStore("my.keystore", "123456");
        // 读取私钥
        PrivateKey mykey = (PrivateKey) ks.getKey("mycert", "123456".toCharArray());
        // 读取证书
        X509Certificate mycert = (X509Certificate) ks.getCertificate("mycert");

        // 加密
        byte[] encrypt = encrypt(mycert, data);

        // 解密
        byte[] decrypt = decrypt(mykey, encrypt);
        System.out.println("Decrypt: " + HexFormat.of().formatHex(decrypt));

        // 签名
        byte[] sign = sign(mykey, mycert, data);
        System.out.println("Sign: " + HexFormat.of().formatHex(sign));

        // 验签
        boolean verify = verify(mycert, data, sign);
        System.out.println("Verify: " + verify);
    }

    public KeyStore loadKeyStore(String keyStoreFile, String password) {
        try (InputStream input = CertificateMain.class.getResourceAsStream(keyStoreFile)) {
            if (input == null) {
                throw new RuntimeException("file not found in classpaht: " + keyStoreFile);
            }
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(input, password.toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(X509Certificate certificate, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
        return cipher.doFinal(message);
    }

    public byte[] decrypt(PrivateKey privateKey, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(message);
    }

    public byte[] sign(PrivateKey privateKey, X509Certificate certificate, byte[] message) throws Exception {
        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    public boolean verify(X509Certificate certificate, byte[] message, byte[] signValue) throws Exception {
        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initVerify(certificate);
        signature.update(message);
        return signature.verify(signValue);

    }


}
