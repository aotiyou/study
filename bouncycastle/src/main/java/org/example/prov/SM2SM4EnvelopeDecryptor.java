package org.example.prov;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

public class SM2SM4EnvelopeDecryptor {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 用SM2私钥解密加密的SM4密钥
    public static byte[] decryptSM4Key(byte[] encryptedKey, PrivateKey sm2PrivateKey) throws Exception {
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2); // 国密推荐使用这个模式
        AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(sm2PrivateKey.getEncoded());

        engine.init(false, privateKeyParam); // false表示解密
        return engine.processBlock(encryptedKey, 0, encryptedKey.length);
    }

    // 用SM4解密数据
    public static byte[] decryptSM4(byte[] encryptedData, byte[] sm4Key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(sm4Key, "SM4");

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) throws Exception {
        // Base64 编码的数据（应从 JSON 或封装结构中提取）
        byte[] encryptedSM4Key = Base64.decode("BASE64_ENCRYPTED_SM4_KEY");
        byte[] encryptedData = Base64.decode("BASE64_ENCRYPTED_DATA");

        String priKeyPem = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg8ZV9Q6KVxeMhYFuF" +
                "SxVgC5BgOMW1OCONizB7sqeea8egCgYIKoEcz1UBgi2hRANCAARuGBGLq4Jon5ik" +
                "PsCFzKaOat+pwCJDbBrphYdJ39M2SjSSbM314eotpzjLvPatz5QLGCmZMUWFoRfl" +
                "kLqU/Rfy";
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(ASN1Sequence.fromByteArray(Base64.decode(priKeyPem)));
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
        KeyFactory fact = KeyFactory.getInstance("EC");
        PrivateKey sm2PrivateKey = fact.generatePrivate(privSpec);

        // SM2 私钥加载
//        PrivateKey sm2PrivateKey = ""; // 加载方式可以是 PKCS8、PEM、pfx 等

        // 解密SM4密钥
        byte[] sm4Key = decryptSM4Key(encryptedSM4Key, sm2PrivateKey);

        // 解密数据
        byte[] decryptedData = decryptSM4(encryptedData, sm4Key);
        System.out.println("解密后的明文内容: " + new String(decryptedData, StandardCharsets.UTF_8));
    }
}
