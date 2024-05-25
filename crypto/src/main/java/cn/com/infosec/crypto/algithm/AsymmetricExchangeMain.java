package cn.com.infosec.crypto.algithm;

import org.bouncycastle.util.encoders.HexEncoder;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2024/5/22
 */
public class AsymmetricExchangeMain {

    @Test
    public void test() throws Exception {
        // 明文
        String message = "Hello, world!";
        byte[] plain = message.getBytes(StandardCharsets.UTF_8);

        // 创建公钥/私钥对
        Person alice = new Person("Alice");
        // 用Alice的公钥加密
        byte[] pk = alice.getPublicKey();
        System.out.println("public key: " + HexFormat.of().formatHex(pk));
        byte[] encrypt = alice.encrypt(plain);
        System.out.println("Encrypted: " + HexFormat.of().formatHex(encrypt));
        // 用Alice的私钥解密
        byte[] sk = alice.getPrivateKey();
        System.out.println("private key: " + HexFormat.of().formatHex(sk));
        byte[] decrypt = alice.decrypt(encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }

    class Person{
        public final String name;
        public PublicKey publicKey;
        private PrivateKey privateKey;
        private byte[] secretKey;

        public Person(String name) throws Exception {
            this.name = name;
            // 生成公钥/私钥对
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
            kpGen.initialize(1024);
            KeyPair kp = kpGen.generateKeyPair();
             this.publicKey = kp.getPublic();
             this.privateKey = kp.getPrivate();
        }

        // 把私钥导出为字节
        public byte[] getPrivateKey() {
            return this.privateKey.getEncoded();
        }

        // 把公钥导出为字节
        public byte[] getPublicKey() {
            return this.publicKey.getEncoded();
        }

        // 用公钥加密：
        public byte[] encrypt(byte[] message) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
            return cipher.doFinal(message);
        }

        // 用私钥解密
        public byte[] decrypt(byte[] message) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            return cipher.doFinal(message);
        }

    }



}
