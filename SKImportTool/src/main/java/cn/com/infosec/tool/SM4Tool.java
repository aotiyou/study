package cn.com.infosec.tool;

import cn.com.infosec.entity.KeyEntity;
import cn.com.infosec.ucypher.agent.resource.ServerReturnCodes;
import cn.com.infosec.ucypher.agent.sdf.UCypherSDF;
import cn.com.infosec.ucypher.agent.util.HexUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * @author infosec
 * @since 2025/9/24
 */
public class SM4Tool extends Agent {


    public static void main(String[] args) throws Exception {
        String key = "06ec93f3077bb0d64c69be580bf93cee";
        String filename = "D:\\infosec\\项目-CCypher-福建城投\\key_100.76.1.136_2025-08-25_08_34_02.json";

        ObjectMapper objectMapper = new ObjectMapper();
        List<KeyEntity> keyEntityList = objectMapper.readValue(new File(filename), new TypeReference<List<KeyEntity>>() {});

        System.out.println("read key json, keyEntityList size = " + keyEntityList.size());

        for (int i = 0; i < keyEntityList.size(); i++) {
            KeyEntity keyEntity = keyEntityList.get(i);
            String keyDataPadding = keyEntity.getKeyData();
            String keyData = keyDataPadding.substring(0, 32);
            byte[] bytes = HexFormat.of().parseHex(keyData);

            byte[] rawKeyBytes = doDecodeKeyWithSm4(key, bytes);

            String rawKeyHashHex = doSm3DigestToHex(rawKeyBytes);
            if(!rawKeyHashHex.equalsIgnoreCase(keyEntity.getKeyHash())) {
                System.out.println("rawKeyHashHex = " + rawKeyHashHex);
                System.out.println("keyHashHex = " + keyEntity.getKeyHash());
            }

            int keyIndex = i + 1;
            int ret = agent.SDFImportSK(keyIndex, "SM4", true, rawKeyBytes);
            if (ret != ServerReturnCodes.SUCCESS) {
                System.out.println("Fail SDFImportSK keyIndex = " + keyIndex + " , ret = " + ret + ", lastMsg=" + agent.getLastMsg());
            }else {
                System.out.println("Success SDFImportSK keyIndex =  " + keyIndex);
            }
        }

    }

    private static byte[] doDecodeKeyWithSm4(String key, byte[] encryptData) throws Exception {
        byte[] keyBytes = HexFormat.of().parseHex(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "SM4");

        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypt = cipher.doFinal(encryptData);
        return decrypt;
    }

    private static String doSm3DigestToHex(byte[] data) throws Exception {
        MessageDigest sm3 = MessageDigest.getInstance("SM3", new BouncyCastleProvider());

        byte[] digest = sm3.digest(data);
        return HexFormat.of().formatHex(digest);
    }

    private static void testRandom() {
        int length = 192;
        ByteBuffer randomBuf = ByteBuffer.allocate(length);
        int ret = agent.SDFGenerateRandom(length, randomBuf);
        if (ret != ServerReturnCodes.SUCCESS) {
            System.out.println("Fail testRandom, ret = " + ret + ", lastMsg=" + agent.getLastMsg());
        }
        byte[] random = UCypherSDF.getDataInBuffer(randomBuf);
        System.out.println("random = " + HexUtil.byte2Hex(random));
    }

}
