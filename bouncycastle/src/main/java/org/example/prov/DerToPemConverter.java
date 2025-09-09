package org.example.prov;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.security.Security;

public class DerToPemConverter {

    public static void main(String[] args) throws Exception {
        // 添加 BC 提供者（可选）
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // DER 证书路径
        String derPath = "D:\\infosec\\项目-国家税务局\\example.com[13030000026c33]\\boya.cer";
        // 输出 PEM 文件路径
        String pemPath = "D:\\infosec\\项目-国家税务局\\example.com[13030000026c33]\\boya.pem";

        try (InputStream in = new FileInputStream(new File(derPath))) {
            X509CertificateHolder holder = new X509CertificateHolder(in.readAllBytes());

            try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(pemPath)))) {
                writer.writeObject(holder);
                writer.flush();
            }
        }

        System.out.println("转换完成，输出文件：" + pemPath);
    }
}
