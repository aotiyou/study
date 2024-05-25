package cn.com.infosec.crypto.algithm;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2024/5/22
 */
public class SignatureMain {

    @Test
    public void test() throws Exception {

        // 生成RSA公钥/私钥
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair keyPair = kpGen.generateKeyPair();
        PrivateKey sk = keyPair.getPrivate();
        PublicKey pk = keyPair.getPublic();

        // 待签名的消息
        String message = "hello world";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        // 用私钥签名
        Signature s = Signature.getInstance("SHA1withRSA");
        s.initSign(sk);
        s.update(data);
        byte[] signed = s.sign();
        System.out.println("signature: " + HexFormat.of().formatHex(signed));

        // 用公钥验证
        s = Signature.getInstance("SHA1withRSA");
        s.initVerify(pk);
        s.update(data);
        boolean verified = s.verify(signed);
        System.out.println("verified: " + verified);

    }

}
