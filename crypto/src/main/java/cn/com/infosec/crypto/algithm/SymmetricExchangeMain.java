package cn.com.infosec.crypto.algithm;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2024/5/22
 */
public class SymmetricExchangeMain {

    @Test
    public void test() {
        // Bob and Alice
        Person bob = new Person("Bob");
        Person alice = new Person("Alice");

        // 各自生成KeyPair
        bob.generateKeyPair();
        alice.generateKeyPair();

        // 双方交换各自的PublicKey
        // Bob根据Alice的PublicKey生成自己的本地密钥
        bob.generateSecretKey(alice.publicKey.getEncoded());

        // Alice根据Bob的PublicKey生成自己的本地密钥
        alice.generateSecretKey(bob.publicKey.getEncoded());

        // 检查双发的本地密钥是否相同
        bob.printKeys();
        alice.printKeys();

        // 双方的SecretKey相同，后续通信将使用SecretKey作为密钥进行AES加解密...
    }

    class Person{
        public final String name;
        public PublicKey publicKey;
        private PrivateKey privateKey;
        private byte[] secretKey;

        public Person(String name) {
            this.name = name;
        }

        // 生成本地KeyPair
        public void generateKeyPair() {
            try {
                KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH");
                kpGen.initialize(512);
                KeyPair kp = kpGen.generateKeyPair();
                this.privateKey = kp.getPrivate();
                this.publicKey = kp.getPublic();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public void generateSecretKey(byte[] receivedPubKeyBytes) {
            try{
                // 从byte[]恢复PublicKey
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPubKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("DH");
                PublicKey receivedPublicKey = kf.generatePublic(keySpec);
                // 生成本地密钥
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(this.privateKey); // 自己的PrivateKey
                keyAgreement.doPhase(receivedPublicKey, true); // 对方的PublicKey
                // 生成SecretKey
                this.secretKey = keyAgreement.generateSecret();
            }catch (Exception e) {
                throw new RuntimeException(e);
            }

        }

        public void printKeys() {
            System.out.println("Name: " + this.name);
            System.out.println("Private key: " + HexFormat.of().formatHex(this.privateKey.getEncoded()));
            System.out.println("Public key: " + HexFormat.of().formatHex(this.publicKey.getEncoded()));
            System.out.println("Secret key: " + HexFormat.of().formatHex(this.secretKey));
        }
    }



}
