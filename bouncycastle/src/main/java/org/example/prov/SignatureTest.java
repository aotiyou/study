package org.example.prov;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;


/**
 * @author aotiyou
 * @since 2025/8/26
 */
public class SignatureTest {

    /**
     * pkcs1 success
     */
    @Test
    public void testASN1Digest() throws Exception {
        String firmaCompuesta = "111111";
        String hashingAlgorithm = "SHA-256";

        boolean useBouncyCastleProvider = true;

        Provider provider = null;
        if (useBouncyCastleProvider) {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }

        MessageDigest messageDigestProvider = null;
        if (null != provider) {
            messageDigestProvider = MessageDigest.getInstance(hashingAlgorithm, provider);
        } else {
            messageDigestProvider = MessageDigest.getInstance(hashingAlgorithm);
        }
        messageDigestProvider.update(firmaCompuesta.getBytes());

        byte[] hash = messageDigestProvider.digest();
        System.out.println("hash = " + HexFormat.of().formatHex(hash));

        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(hashingAlgorithm);

        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hash);
        byte[] hashToEncrypt = digestInfo.getEncoded();
        System.out.println("hashToEncrypt = " + HexFormat.of().formatHex(hashToEncrypt));

        ASN1Primitive primitive = ASN1Primitive.fromByteArray(hashToEncrypt);

        // 2. 转换为 DigestInfo
        DigestInfo di = DigestInfo.getInstance(primitive);

        // 3. 提取原始 hash
        byte[] digest = di.getDigest();
        System.out.println("digest = " + HexFormat.of().formatHex(digest));

    }

    /**
     * pss
     */
    @Test
    public void testRSASignAndVerify() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        // 做hash，32、48、64 sha256 sm3
        byte[] data = new byte[32];

        // SHA256withRSAandMGF1 NONEwithRSAandMGF1 NONEWITHRSAPSS SHA256WithRSASSA-PSS
        Signature signature = Signature.getInstance("SHA256WithRSASSA-PSS", new BouncyCastleProvider());
        MGF1ParameterSpec mgfParam = new MGF1ParameterSpec("SHA256");
        PSSParameterSpec pssParam = new PSSParameterSpec("SHA256", "MGF1", mgfParam, 32, 1);
        signature.setParameter(pssParam);

        // sign 使用crypto去签
        signature.initSign(privateKey);
        signature.update(data);
        byte[] sign = signature.sign();
        System.out.println("HexFormat.of().formatHex(sign) = " + HexFormat.of().formatHex(sign));

        // verify 使用华为自己的验
        signature.initVerify(aPublic);
        signature.update(data);
        boolean verify = signature.verify(sign);
        System.out.println("verify = " + verify);

    }


    @Test
    public void test3() throws Exception {
        byte[] data = new byte[32];
        System.out.println("data.length = " + data.length);
        System.out.println("Base64.getEncoder().encodeToString(data) = " + Base64.getEncoder().encodeToString(data));
        System.out.println("Base64.getEncoder().encodeToString(data) = " + Base64.getEncoder().encodeToString(data).length());
    }

    @Test
    public void testSM2SignAndVerify() throws Exception {
        byte[] uid = "1234567812345678".getBytes();
        byte[] data = new byte[32];

        // 1. 生成 SM2 密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        keyPairGenerator.initialize(sm2Spec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey)keyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey)keyPair.getPublic();

        System.out.println("publicKey = " + HexFormat.of().formatHex(publicKey.getEncoded()));
        System.out.println("privateKey = " + HexFormat.of().formatHex(privateKey.getEncoded()));

        // 2. 构造 domain 参数
        ECNamedCurveParameterSpec parameters = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECDomainParameters domainParameters = new ECDomainParameters(
                parameters.getCurve(), parameters.getG(), parameters.getN());


        X9ECParameters sm2p256v1 = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2p256v1.getCurve(),
                sm2p256v1.getG(),
                sm2p256v1.getN(),
                sm2p256v1.getH()
        );

        // 2. 从你的 SM2refPublicKey 中获取 X、Y，组装 ECPoint
        BigInteger x = new BigInteger(1, publicKey.getW().getAffineX().toByteArray());
        BigInteger y = new BigInteger(1, publicKey.getW().getAffineY().toByteArray());
        ECPoint ecPoint = sm2p256v1.getCurve().createPoint(x, y);

        // 3. 签名
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), domainParameters);
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(true, new ParametersWithID(ecPrivateKeyParameters, uid));
        sm2Signer.update(data, 0, data.length);
        byte[] signatureData = sm2Signer.generateSignature();
        System.out.println("signatureData = " + HexFormat.of().formatHex(signatureData));

        // 4. 验签
//        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), domainParameters);
        ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(ecPoint, domainParams);
        SM2Signer sm2Verify = new SM2Signer();
        sm2Verify.init(false, new ParametersWithID(pubKeyParams, uid));
        sm2Verify.update(data, 0, data.length);
        boolean verified = sm2Verify.verifySignature(signatureData);
        System.out.println("verified = " + verified);

    }

    @Test
    public void testSM2EncAndDec() throws Exception {
        // 1. SM2 曲线参数
        X9ECParameters sm2p256v1 = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2p256v1.getCurve(), sm2p256v1.getG(), sm2p256v1.getN(), sm2p256v1.getH()
        );

        // 2. 生成 SM2 密钥对
        ECKeyGenerationParameters genParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(genParams);
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

        // 待加密数据
        byte[] input = "Hello, SM2 with ASN.1!".getBytes();

        // 3. SM2 加密
        SM2Engine sm2Enc = new SM2Engine();
        sm2Enc.init(true, new ParametersWithRandom(pubKey, new SecureRandom()));
        byte[] cipherText = sm2Enc.processBlock(input, 0, input.length);

        System.out.println("cipherText = " + HexFormat.of().formatHex(cipherText));

        // 4. 将密文封装成 ASN.1 SEQUENCE
        ASN1EncodableVector v = new ASN1EncodableVector();
        int c1Len = 65; // 默认 uncompressed ECPoint
        byte[] c1 = Arrays.copyOfRange(cipherText, 0, c1Len);
        byte[] c3 = Arrays.copyOfRange(cipherText, c1Len, c1Len + 32);
        byte[] c2 = Arrays.copyOfRange(cipherText, c1Len + 32, cipherText.length);

        v.add(new DEROctetString(c1));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));

        byte[] asn1Cipher = new DERSequence(v).getEncoded();
        System.out.println("ASN.1 CipherText (hex): " + HexFormat.of().formatHex(asn1Cipher));

        // 5. 从 ASN.1 解析密文
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(asn1Cipher);
        byte[] decC1 = ((ASN1OctetString) seq.getObjectAt(0)).getOctets();
        byte[] decC3 = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
        byte[] decC2 = ((ASN1OctetString) seq.getObjectAt(2)).getOctets();

        // 拼回 SM2Engine 原始格式
        byte[] rawCipher = new byte[decC1.length + decC2.length + decC3.length];
        System.arraycopy(decC1, 0, rawCipher, 0, decC1.length);
        System.arraycopy(decC3, 0, rawCipher, decC1.length, decC3.length);
        System.arraycopy(decC2, 0, rawCipher, decC1.length + decC3.length, decC2.length);

        // 6. SM2 解密
        SM2Engine sm2Dec = new SM2Engine();
        sm2Dec.init(false, priKey);
        byte[] decrypted = sm2Dec.processBlock(rawCipher, 0, rawCipher.length);

        System.out.println("Decrypted Text: " + new String(decrypted));
    }

    @Test
    public void testECDSASignAndVerify() throws Exception {
        // 1. 注册 BC Provider
        Security.addProvider(new BouncyCastleProvider());

        // 2. 生成 ECDSA 密钥对 (secp256r1 = prime256v1)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp521r1"), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("privateKey = " + HexFormat.of().formatHex(privateKey.getEncoded()));
        System.out.println("publicKey = " + HexFormat.of().formatHex(publicKey.getEncoded()));

        // 3. 待签名数据
        byte[] message = "hello ecdsa".getBytes();
        System.out.println("message = " + HexFormat.of().formatHex(message));

        // 4. 签名
        Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();
        System.out.println("签名 (hex) = " + HexFormat.of().formatHex(signature));

//        byte[] message = "12345678".getBytes();
//        String publicKeyHex = "30819b301006072a8648ce3d020106052b810400230381860004019113bf0a6ea80658a812b8fc9b0cf01b8efff5399408a0d3fbfc5bbafbe7e3423c4006da03d94122da1fc648854577eeb110a1e985c2b270bd184a72082f186dd9005a8a6bc7cfcd041acd06901082c476a886466a8abc4a7b19f7e0e12b12e84e5b9fecfa52060ded8a49b8607472fa8c9718b55cafd2795a637c861a5730645ec77d";
//        String signatureHex = "308187024201cac852a6a2e1718f9ccccf7c2f346c84193d2b8d1ad3696d348057a75bda2aa704a1ee032b46aae60ec206e67993f857da0574caca2bc28eee961e58166a7dcf7902414e95b199dfe6801de2e4588df3f1a315c4f0511bb09c6eaf4c26785ab994079adad23e4ce520b7c26cfdf3734a8b3cf9214e0121407bead2ea5c9efe834831f835";
//
//        // 解析公钥
//        byte[] pubKeyBytes = Hex.decode(publicKeyHex);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyBytes);
//        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
//        PublicKey publicKey = kf.generatePublic(keySpec);
//
//        // 解析签名
//        byte[] sigBytes = Hex.decode(signatureHex);
//
//        // 5. 验签
//        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
//        verifier.initVerify(publicKey);
//        verifier.update(message);
//        boolean ok = verifier.verify(sigBytes);
//        System.out.println("验签结果 = " + ok);
    }

    @Test
    public void testEDDSASignAndVerify() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1. 生成密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey sk = kp.getPrivate();
        PublicKey pk = kp.getPublic();

        System.out.println("sk = " + HexFormat.of().formatHex(sk.getEncoded()));
        System.out.println("pk = " + HexFormat.of().formatHex(pk.getEncoded()));

        byte[] msg = "hello ed25519".getBytes();

        String pubStr = "302a300506032b65700321005883d4b75a2d421899862396197108040fb4af76a7046c9aba749acd139e0018";

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(HexFormat.of().parseHex(pubStr));
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
        PublicKey pubKey = kf.generatePublic(keySpec);

        System.out.println("pk = " + HexFormat.of().formatHex(pk.getEncoded()));

        // 2. 签名
        Signature sig = Signature.getInstance("Ed25519", "BC");
        sig.initSign(sk);
        sig.update(msg);
        byte[] signature = sig.sign();
        System.out.println("sig = " + HexFormat.of().formatHex(signature)); // 64字节

        // 3. 验签
        Signature verifier = Signature.getInstance("Ed25519", "BC");
        verifier.initVerify(pubKey);
        verifier.update(msg);
        boolean ok = verifier.verify(signature);
        System.out.println("verify = " + ok);

        byte[] msg1 = "222".getBytes();
        String signHex = "302a300506032b657003210080c5fb25cd9d0d96e410ace69e924b945182ef5517e2d4d5d38ea34e1d41e6a9680d0b404747a0abb0fa93336f68ba7cdfbf687394a2e8b2eae4118b03a0670f";
        String pubHex = "302a300506032b65700321005883d4b75a2d421899862396197108040fb4af76a7046c9aba749acd139e0018";

        byte[] signatureBytes = HexFormat.of().parseHex(signHex);

        // 解析公钥
        byte[] pubKeyBytes = Hex.decode(pubHex);
        X509EncodedKeySpec keySpec1 = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf1 = KeyFactory.getInstance("Ed25519", "BC");
        PublicKey publicKey = kf1.generatePublic(keySpec1);

        // 3. 验签
        Signature verifier1 = Signature.getInstance("Ed25519", "BC");
        verifier1.initVerify(publicKey);
        verifier1.update(msg1);
        boolean ok1 = verifier1.verify(signatureBytes);
        System.out.println("verify = " + ok1);


    }




}
