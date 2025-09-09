package org.example.prov;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class SM2SM4EnvelopeCreator {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 生成随机SM4密钥（128位）
    public static byte[] generateSM4Key() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BC");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        return key.getEncoded();
    }

    // 用SM4加密明文
    public static byte[] encryptSM4(byte[] data, byte[] sm4Key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(sm4Key, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // 用SM2公钥加密SM4密钥
    public static byte[] encryptSM4Key(byte[] sm4Key, PublicKey sm2PublicKey) throws Exception {
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        AsymmetricKeyParameter publicKeyParam = PublicKeyFactory.createKey(sm2PublicKey.getEncoded());

        SecureRandom random = new SecureRandom();
        engine.init(true, new ParametersWithRandom(publicKeyParam, random)); // true = encrypt

        return engine.processBlock(sm4Key, 0, sm4Key.length);
    }

    public static void main(String[] args) throws Exception {
        String plaintext = "这是机密内容";

        // 1. 准备SM4密钥
        byte[] sm4Key = generateSM4Key();

        // 2. 加密数据
        byte[] encryptedData = encryptSM4(plaintext.getBytes("UTF-8"), sm4Key);

        // 3. 加载接收方SM2公钥（你需要替换成自己的）
        String pubKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEbhgRi6uCaJ+YpD7AhcymjmrfqcAiQ2wa6YWHSd/TNko0kmzN9eHqLac4y7z2rc+UCxgpmTFFhaEX5ZC6lP0X8g==";
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        X509Certificate x509Certificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(pubKey)));

        SubjectPublicKeyInfo ski = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(java.util.Base64.getDecoder().decode(pubKey)));
        X509EncodedKeySpec eks = new X509EncodedKeySpec(ski.getEncoded());
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey sm2PublicKey = kf.generatePublic(eks);

//        PublicKey sm2PublicKey = x509Certificate.getPublicKey(); // 从 X509 证书或公钥加载

        // 4. 加密SM4密钥
        byte[] encryptedKey = encryptSM4Key(sm4Key, sm2PublicKey);

        // 5. 输出数字信封结构
        Map<String, String> envelope = new HashMap<>();
        envelope.put("encryptedKey", Base64.toBase64String(encryptedKey));
        envelope.put("encryptedData", Base64.toBase64String(encryptedData));

        System.out.println("数字信封内容：");
        System.out.println(envelope);
    }
}
