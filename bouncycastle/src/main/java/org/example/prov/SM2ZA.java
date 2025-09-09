//package org.example.prov;
//
//import org.bouncycastle.asn1.gm.GMNamedCurves;
//import org.bouncycastle.crypto.digests.SM3Digest;
//import org.bouncycastle.crypto.params.ECDomainParameters;
//import org.bouncycastle.crypto.params.ECPublicKeyParameters;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
//import org.bouncycastle.crypto.signers.SM2Signer;
//import org.bouncycastle.crypto.util.SM2Util;
//
//import java.nio.charset.StandardCharsets;
//import java.security.*;
//import java.util.Base64;
//
//public class SM2ZA {
//
//    public static byte[] calculateZA(PublicKey publicKey, String userId) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
//
//        // SM2 椭圆曲线参数（固定）
//        ECDomainParameters domainParams = GMNamedCurves.getByName("sm2p256v1");
//
//        // 强制转换为 BCECPublicKey 以便获取坐标
//        BCECPublicKey ecPub = (BCECPublicKey) publicKey;
//        ECPoint q = ecPub.getQ(); // 公钥 Q = (xA, yA)
//
//        ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(q, domainParams);
//
//        byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8);
//
//        // 计算 ZA 值
//        return SM2Util.getZ(new SM3Digest(), userIdBytes, pubKeyParams);
//    }
//
//    public static void main(String[] args) throws Exception {
//        // 假设你已经有公钥对象（比如从 Base64 解码后得到）
//        String base64Key = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEcujq+N4T2EeH0cjUPlnh/bI+f8Oa4vnAfVs2fg3O9KaA79dZbqXQsge0W+2EsxJWpVbiZ5v2T5759RgryaapIA==";
//        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
//
//        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
//        PublicKey publicKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(keyBytes));
//
//        byte[] za = calculateZA(publicKey, "1234567812345678");
//
//        System.out.println("ZA: " + bytesToHex(za));
//    }
//
//    public static String bytesToHex(byte[] data) {
//        StringBuilder sb = new StringBuilder();
//        for (byte b : data) {
//            sb.append(String.format("%02x", b));
//        }
//        return sb.toString();
//    }
//}
