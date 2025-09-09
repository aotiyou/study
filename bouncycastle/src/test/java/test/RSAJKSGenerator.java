package test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class RSAJKSGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // 生成 RSA 密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 创建自签名证书
        X509Certificate cert = generateSelfSignedCertificate(keyPair);

        // 创建 JKS
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        // 将私钥和证书添加到 JKS
        keyStore.setKeyEntry("jcesign", keyPair.getPrivate(), "123456".toCharArray(), new Certificate[]{cert});

        // 保存 JKS 到文件
        try (FileOutputStream fos = new FileOutputStream("keystore.jks")) {
            keyStore.store(fos, "123456".toCharArray());
        }

        System.out.println("JKS file created successfully.");
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=Test Certificate");

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); // 使用相同的 DN 作为颁发者和主题
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
    }
}

