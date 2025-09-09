package org.example.prov;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * @author infosec
 * @since 2025/4/11
 */
public class SM2KeyTest {

    public static void main(String[] args) throws Exception {
// 添加 BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // 获取 SM2 的参数 (中国标准推荐曲线 sm2p256v1)
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");

        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 输出 Base64 编码结果
        System.out.println("SM2 Public Key (Base64):");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        System.out.println("SM2 Private Key (Base64):");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));


    }

}
