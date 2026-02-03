package org.example.prov;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * @author infosec
 * @since 2025/10/30
 */
public class KeyPairTest {

    @Test
    public void testGenKeyPair_RSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        System.out.println("rsa aPrivate = " + Hex.toHexString(aPrivate.getEncoded()));
        System.out.println("rsa aPublic = " + Hex.toHexString(aPublic.getEncoded()));
    }

    @Test
    public void testGenKeyPair_SM2() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        keyPairGenerator.initialize(sm2Spec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        System.out.println("sm2 aPrivate = " + Hex.toHexString(aPrivate.getEncoded()));
        System.out.println("sm2 aPublic = " + Hex.toHexString(aPublic.getEncoded()));
    }

    @Test
    public void testGenKeyPair_ECC() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        keyGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        System.out.println("ecc aPrivate = " + Hex.toHexString(aPrivate.getEncoded()));
        System.out.println("ecc aPublic = " + Hex.toHexString(aPublic.getEncoded()));
    }

    @Test
    public void testGenKeyPair_ED25519() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider());
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        System.out.println("ed25519 aPrivate = " + Hex.toHexString(aPrivate.getEncoded()));
        System.out.println("ed25519 aPublic = " + Hex.toHexString(aPublic.getEncoded()));
    }


}
