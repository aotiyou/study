package cn.com.zxy.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * @author infosec
 * @since 2025/10/26
 */
public class Main {

    @org.junit.jupiter.api.Test
    public void testCipherECC_ECIES() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1️⃣ 生成 ECC 密钥对（使用 prime256v1）
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        System.out.println("公钥: " + keyPair.getPublic());
        System.out.println("私钥: " + keyPair.getPrivate());

        // 2️⃣ 初始化 ECIES Cipher
        Cipher cipherEnc = Cipher.getInstance("ECIES", "BC");
        cipherEnc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), new SecureRandom());

        String plaintext = "Hello ECC encryption!";
        byte[] ciphertext = cipherEnc.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        System.out.println("密文(hex): " + Hex.toHexString(ciphertext));

        // 3️⃣ 解密
        Cipher cipherDec = Cipher.getInstance("ECIES", "BC");
        cipherDec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), new SecureRandom());
        byte[] decrypted = cipherDec.doFinal(ciphertext);
        System.out.println("解密后明文: " + new String(decrypted, StandardCharsets.UTF_8));

    }

    @org.junit.jupiter.api.Test
    public void testSignatureECC_ECDSA() throws Exception {
        // 1️⃣ 注册 BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // 2️⃣ 生成 EC 密钥对（曲线 prime256v1 / secp256r1）
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("私钥: " + privateKey);
        System.out.println("公钥: " + publicKey);

        // 3️⃣ 待签名消息
        String message = "Hello ECDSA! 椭圆曲线签名测试";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // 4️⃣ 签名（SHA256withECDSA）
        Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
        signer.initSign(privateKey);
        signer.update(messageBytes);
        byte[] signature = signer.sign();

        String signatureB64 = Hex.toHexString(signature);
        System.out.println("签名(Base64): " + signatureB64);

        // 5️⃣ 验证签名
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(messageBytes);
        boolean ok = verifier.verify(signature);

        System.out.println("验签结果: " + ok);
    }


    @Test
    public void testECDSA() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider());
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = (PublicKey)keyPair.getPublic();
        PrivateKey privateKey = (PrivateKey)keyPair.getPrivate();

        System.out.println("私钥: " + new BigInteger(1, privateKey.getEncoded()).toString(16));
        System.out.println("公钥: " + new BigInteger(1, publicKey.getEncoded()).toString(16));

        // 3️⃣ 待签名消息
        String message = "Hello ED25519! 椭圆曲线签名测试";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // 4️⃣ 签名（SHA256withECDSA）
        Signature signer = Signature.getInstance("Ed25519", "BC");
        signer.initSign(privateKey);
        signer.update(messageBytes);
        byte[] signature = signer.sign();

        String signatureB64 = Hex.toHexString(signature);
        System.out.println("签名(Base64): " + signatureB64);

        // 5️⃣ 验证签名
        Signature verifier = Signature.getInstance("Ed25519", "BC");
        verifier.initVerify(publicKey);
        verifier.update(messageBytes);
        boolean ok = verifier.verify(signature);

        System.out.println("验签结果: " + ok);
    }

}
