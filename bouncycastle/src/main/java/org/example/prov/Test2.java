package org.example.prov;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
//import java.util.HexFormat;
//import java.util.HexFormat;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Test2 {

	public static void main(String[] args) throws Exception {
//		Security.addProvider(new BouncyCastleProvider());

		String signcert = "-----BEGIN CERTIFICATE-----\r\n" +
				"MIID1zCCA36gAwIBAgIIc+lAdyLLqNswCgYIKoEcz1UBg3UwgYIxCzAJBgNVBAYT\r\n" +
				"AkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMScwJQYD\r\n" +
				"VQQKDB5TaGVuWmhlbiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxDTALBgNVBAsMBHN6\r\n" +
				"Y2ExFDASBgNVBAMMC1NaQ0EgU00yIENBMB4XDTIzMTEyODA4MTU0N1oXDTI0MTEy\r\n" +
				"NzA4MTU0N1owgbAxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAnlub/kuJznnIExEjAQ\r\n" +
				"BgNVBAcMCeW5v+W3nuW4gjEVMBMGA1UEDAwMMjAyMzExMjgxMTA3MTMwMQYDVQQK\r\n" +
				"DCrnnIHkuqTpgJrljoXlubLnur/lhazot6/lhbvmiqTns7vnu5/mtYvor5UxGzAZ\r\n" +
				"BgNVBAsMEjExMTAwMDAwMDAwMDAwMDAxMTEQMA4GA1UEAwwH5rWL6K+VMTBZMBMG\r\n" +
				"ByqGSM49AgEGCCqBHM9VAYItA0IABLXu7XRdIMUqDBiXncKILNzFH5SPfk+OqjGb\r\n" +
				"Eizrr0ULH482I4At/zIm5Y4ZtvlY8BHzoCnhCDaaopdLd77kVeGjggGsMIIBqDAJ\r\n" +
				"BgNVHRMEAjAAMB8GA1UdIwQYMBaAFIp7RlrOEWXYU7lRekLvRz0KjLjoMIGKBggr\r\n" +
				"BgEFBQcBAQR+MHwwIwYIKwYBBQUHMAKGF2h0dHA6Ly9jYWlzc3VlLnN6Y2EubmV0\r\n" +
				"MCAGCCsGAQUFBzAChhRodHRwOi8vbGRhcC5zemNhLm5ldDAzBggrBgEFBQcwAYYn\r\n" +
				"aHR0cDovL29jc3Auc3pjYS5jb206ODA5MS9vY3NwL2Fuc2lPY3NwMEwGA1UdIARF\r\n" +
				"MEMwQQYEVR0gADA5MDcGCCsGAQUFBwIBFitodHRwczovL3d3dy5zemNhLmNvbS9z\r\n" +
				"ZXJ2aWNlL0NQUy9pbmRleC5odG1sMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9j\r\n" +
				"cmwuc3pjZXJ0LmNvbS9lY2MvY3JsLmNybDAdBgNVHQ4EFgQUvBYkTCd60tBhfyeH\r\n" +
				"ZJVOa55XChkwCwYDVR0PBAQDAgbAMBAGCCpWCweDzOoQBAQMAkNTMC0GBmCBHIbv\r\n" +
				"JAQjDCExQDcwMjVTRjFNVEl6TVRJek1USXpNVEl6TVRVMk5qWTIwCgYIKoEcz1UB\r\n" +
				"g3UDRwAwRAIgCihwYDv2e0CY1bHKs4YHiacgSzTnzzpkAY/d0CTU63ICIG+Jwsst\r\n" +
				"PkrpgaBabHtz50hdS8kpfl2SlbvFOvB5+TPC\r\n" +
				"-----END CERTIFICATE-----\r\n" +
				"";
		String signdata = "MEUCIQCu+byWl/FO37DljPwgND8VLfipbVOBl31A5TPrUpoknAIgPCVGbdmdXLDU4/hKIZhgfvtkdZ6f+A4epcVbeOdcc5k=";
		String data = "agcomadmin_7lghch4ijffnnqbj";

		X509Certificate cert = getX509Certificate(signcert);

		byte[] b = cert.getPublicKey().getEncoded();
//		System.out.println(HexFormat.of().formatHex(b));
		PublicKey publicKey =  cert.getPublicKey();

		// 获取公钥中的X和Y
		ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
		// 通过 getW() 方法获取 EC 点，该点包含了 x 和 y 坐标
		ECPoint ecPoint = ecPublicKey.getW();

		// 提取 x 坐标和 y 坐标
		BigInteger x = ecPoint.getAffineX();
		BigInteger y = ecPoint.getAffineY();

		// 输出坐标（可选）
		System.out.println("x: " + x.toString(16));
		System.out.println("y: " + y.toString(16));


//		Signature ver = Signature.getInstance("SM3withSM2", "BC");
//        ver.initVerify(cert.getPublicKey());
//        ver.update(Base64.decode("YWdjb21hZG1pbl83bGdoY2g0aWpmZm5ucWJq"));
//        boolean flag = ver.verify(Base64.decode(signdata));
//        System.out.println(flag);

		byte[] a = Base64.getDecoder().decode(signdata);

//		System.out.println(HexFormat.of().formatHex(a));

		// 使用 BouncyCastle 的 ASN1InputStream 解析 DER 编码的签名结构
		ASN1InputStream asn1InputStream = new ASN1InputStream(a);
		ASN1Primitive asn1Primitive = asn1InputStream.readObject();
		asn1InputStream.close();

		// 转换为 ASN1Sequence，内部应包含两个整数
		ASN1Sequence sequence = (ASN1Sequence) asn1Primitive;
		// 从序列中分别取得 r 和 s
		ASN1Integer rAsn1 = (ASN1Integer) sequence.getObjectAt(0);
		ASN1Integer sAsn1 = (ASN1Integer) sequence.getObjectAt(1);
		BigInteger r = rAsn1.getValue();
		BigInteger s = sAsn1.getValue();

		System.out.println("签名参数 r: " + r.toString(16));
		System.out.println("签名参数 s: " + s.toString(16));

		MessageDigest messageDigest = MessageDigest.getInstance("SM3", "BC");
//		byte[] digest = messageDigest.digest(sourceData);

	}

public static X509Certificate getX509Certificate(String cert) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
	    CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
	    X509Certificate x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getBytes()));
	    return x509cert;
	}



}
