package cn.com.infosec.crypto.algithm;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class HmacMain {
    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
        SecretKey key = keyGen.generateKey();
        byte[] keyEncoded = key.getEncoded();
        System.out.println(HexFormat.of().formatHex(keyEncoded));

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);
        mac.update("hello world".getBytes(StandardCharsets.UTF_8));
        byte[] result = mac.doFinal();
        System.out.println(HexFormat.of().formatHex(result));


    }
}
