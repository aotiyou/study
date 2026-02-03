package org.example.prov;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * @author infosec
 * @since 2025/11/10
 */
public class AsymmetricTest {

    @Test
    public void testRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey priKey = kp.getPrivate();
        PublicKey pubKey  = kp.getPublic();

        byte[] data = "hello world".getBytes("UTF-8");

        // ====== 签名 ======
        Signature signer = Signature.getInstance("SHA256withRSA", new BouncyCastleProvider());
        signer.initSign(priKey);
        signer.update(data);
        byte[] sign = signer.sign();
        System.out.println("sign = " + Hex.toHexString(sign));

        // ====== 验签 ======
        Signature verifier = Signature.getInstance("SHA256withRSA", new BouncyCastleProvider());
        verifier.initVerify(pubKey);
        verifier.update(data);
        boolean ok = verifier.verify(sign);
        System.out.println("verify = " + ok);
    }

    @Test
    public void test2() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();

        System.out.println("priv = " + Hex.toHexString(priv.getEncoded()));

        byte[] msg = "abc".getBytes("UTF-8");

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(priv);
        sig.update(msg);
        byte[] signature = sig.sign();

        System.out.println("signature hex:");
        System.out.println(Hex.toHexString(signature));

        // ============== 解 signature ==============
        BigInteger n = ((java.security.interfaces.RSAPublicKey) pub).getModulus();
        BigInteger sigInt = new BigInteger(1, signature);

        // EM = signature^e mod n
        BigInteger em = sigInt.modPow(BigInteger.valueOf(65537), n);
        byte[] emBytes = BigIntegers.asUnsignedByteArray(256, em); // 2048 bit = 256字节

        System.out.println("EM:");
        System.out.println(Hex.toHexString(emBytes));

        // 跳过 0x00 01 FF..FF 00 找 DigestInfo 的起点
        int i = 2;
        while (emBytes[i] == (byte)0xFF) i++;
        if (emBytes[i] != 0x00) throw new RuntimeException("padding error");
        i++;

        byte[] diBytes = new byte[emBytes.length - i];
        System.arraycopy(emBytes, i, diBytes, 0, diBytes.length);

        System.out.println("DigestInfo DER:");
        System.out.println(Hex.toHexString(diBytes));

        ASN1Primitive p = new ASN1InputStream(diBytes).readObject();
        DigestInfo di = DigestInfo.getInstance(p);
        System.out.println("HASH from DI:");
        System.out.println(Hex.toHexString(di.getDigest()));
    }

}
