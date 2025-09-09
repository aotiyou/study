package org.example.prov;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author infosec
 * @since 2025/6/1
 */
public class BKSTest {

    @Test
    public void test() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String priKeyPem =
                "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg8ZV9Q6KVxeMhYFuF" +
                "SxVgC5BgOMW1OCONizB7sqeea8egCgYIKoEcz1UBgi2hRANCAARuGBGLq4Jon5ik" +
                "PsCFzKaOat+pwCJDbBrphYdJ39M2SjSSbM314eotpzjLvPatz5QLGCmZMUWFoRfl" +
                "kLqU/Rfy";
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(ASN1Sequence.fromByteArray(Base64.decode(priKeyPem)));
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
        KeyFactory fact = KeyFactory.getInstance("EC");
        PrivateKey pri = fact.generatePrivate(privSpec);


        String certPem =
                "MIIBoTCCAUSgAwIBAgIKImAtT5XzeFJ62jAMBggqgRzPVQGDdQUAMCQxEDAOBgNV" +
                "BAMMB1VDcnlwdG8xEDAOBgNVBAoMB2luZm9zZWMwHhcNMjUwNTI5MDkzNDU3WhcN" +
                "MjUwNjI5MDkzNDU3WjAuMRowGAYDVQQDDBFVQ3J5cHRvX3VzZXJfc2lnbjEQMA4G" +
                "A1UECgwHaW5mb3NlYzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABG4YEYurgmif" +
                "mKQ+wIXMpo5q36nAIkNsGumFh0nf0zZKNJJszfXh6i2nOMu89q3PlAsYKZkxRYWh" +
                "F+WQupT9F/KjUjBQMB8GA1UdIwQYMBaAFAHFh06xctoM1XBUObRc0+c/gw3YMB0G" +
                "A1UdDgQWBBQ6fw+bkveK5nL7Jo0JCyeNoRFFvjAOBgNVHQ8BAf8EBAMCB4AwDAYI" +
                "KoEcz1UBg3UFAANJADBGAiEAnsXjkEDNWbshOEkn2fVGtndTzKvs5kLvyEGvI20n" +
                "HusCIQDM4TKjlWS/tKVPCizs+gNmmKBq9ECSpJcOpF70yppxlg==";
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certPem)));

        String outFile = "D:\\certs\\jks\\test11.jks";
        saveAsBks(pri, cert, null, "", outFile);

        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        try (InputStream in = new FileInputStream(outFile)) {
            ks.load(in, "".toCharArray());
            Key key = ks.getKey("alias", "".toCharArray());
            X509Certificate cert2 = (X509Certificate) ks.getCertificate("alias");
            System.out.println(cert2.getSerialNumber());
        }


    }

    public static void saveAsBks(PrivateKey privateKey, X509Certificate cert, Certificate[] chain, String password, String outputFilePath) throws Exception {
        String alias = "alias";

        KeyStore keyStore = KeyStore.getInstance("BKS", "BC");  // "BC" 是 BouncyCastle 的 provider 名称
        keyStore.load(null, null); // 初始化 keystore

        Certificate[] certChain;
        if (chain == null) {
            certChain = new Certificate[]{cert};
        } else {
            certChain = new Certificate[chain.length + 1];
            certChain[0] = cert;
            System.arraycopy(chain, 0, certChain, 1, chain.length);
        }

        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), certChain);

        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            keyStore.store(fos, password.toCharArray());
        }

        System.out.println("BKS keystore saved to: " + outputFilePath);
    }

}
