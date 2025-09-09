package org.example.prov;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
//import java.util.HexFormat;
//import java.util.HexFormat;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;




public class Test {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

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


		byte[] rs = sign2rs(java.util.Base64.getDecoder().decode(signdata));
//		System.out.println("HexFormat.of().formatHex(rs) = " + HexFormat.of().formatHex(rs));

		String data = "agcomadmin_7lghch4ijffnnqbj";

		X509Certificate cert = getX509Certificate(signcert);
		BCECPublicKey publicKey = (BCECPublicKey)cert.getPublicKey();
		BigInteger affineX = publicKey.getW().getAffineX();
		BigInteger affineY = publicKey.getW().getAffineY();

		byte[] x = affineY.toByteArray();
		byte[] y = affineY.toByteArray();


		Signature ver = Signature.getInstance("SM3withSM2", "BC");
        ver.initVerify(cert.getPublicKey());
        ver.update(Base64.decode("YWdjb21hZG1pbl83bGdoY2g0aWpmZm5ucWJq"));
        boolean flag = ver.verify(Base64.decode(signdata));
        System.out.println(flag);

	}

public static X509Certificate getX509Certificate(String cert) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
	    CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
	    X509Certificate x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getBytes()));
	    return x509cert;
	}

//	public static byte[] formatSignedMsg(byte[] signed) {
//		if (signed.length == 64) {
//			return signed;
//		} else {
//			while(signed[0] == 0) {
//				byte[] tmp = new byte[signed.length - 1];
//				System.arraycopy(signed, 1, tmp, 0, tmp.length);
//				signed = tmp;
//			}
//
//			if (signed[0] != 48) {
////				throw new VerifySignatureException("Bad signature struction");
//			} else {
//				byte[] signedf = new byte[64];
//
//				try {
//					DERSegment ds = new DERSegment(signed);
//					ds = ds.getInnerDERSegment();
//					byte[] tmp = ds.nextDERSegment().getInnerData();
//					if (tmp.length >= 32) {
//						System.arraycopy(tmp, tmp.length - 32, signedf, 0, 32);
//					} else {
//						System.arraycopy(tmp, 0, signedf, 32 - tmp.length, tmp.length);
//					}
//
//					tmp = ds.nextDERSegment().getInnerData();
//					if (tmp.length >= 32) {
//						System.arraycopy(tmp, tmp.length - 32, signedf, 32, 32);
//					} else {
//						System.arraycopy(tmp, 0, signedf, 64 - tmp.length, tmp.length);
//					}
//
//					return signedf;
//				} catch (Exception e) {
//					throw new VerifySignatureException(e);
//				}
//			}
//		}
//	}

	private static byte[] sign2rs(byte[] sign) {

		byte[] r = new byte[32];
		byte[] s = new byte[32];

		int x_length = sign[3];
		int y_length = sign[(x_length + 5)];
		if (x_length > 32) {
			System.arraycopy(sign, 4 + x_length - 32, r, 0, 32);
		} else {
			System.arraycopy(sign, 4, r, 32 - x_length, x_length);
		}
		if (y_length > 32) {
			System.arraycopy(sign, 6 + x_length + y_length - 32, s, 0, 32);
		} else {
			System.arraycopy(sign, 6 + x_length, s, 32 - y_length, y_length);
		}
		System.out.println("r.length: " + r.length);
//		ConsoleLogger.logBinary("sign2rs r", r);
		System.out.println("s.length: " + s.length);
//		ConsoleLogger.logBinary("sign2rs s", s);

		byte[] arrayOfByte = new byte[64];
		System.arraycopy(r, 0, arrayOfByte, 0, 32);
		System.arraycopy(s, 0, arrayOfByte, 32, 32);
//		ConsoleLogger.logBinary("sign2rs", arrayOfByte);

		return arrayOfByte;
	}



}
