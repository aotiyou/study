package cn.com.infosec;

import cn.com.infosec.nethsm.crypto.client.CryptoClient;
import cn.com.infosec.ucypher.agent.util.CipherUtil;
import cn.com.infosec.ucypher.agent.util.DataUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2024/12/3
 */
public class Main {

    private static final String path = "D:\\infosec_project\\云密码机-中国电信天翼云POC\\chsm\\src\\web\\backend\\resource\\opt\\infosec\\CCypher\\web\\apps\\data";

//    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
//        LOG.info("================================Heartbeat");
//        CryptoClient client = new CryptoClient("10.210.20.96", "default_user", path);
//        try {
//            client.heartbeat();
//        } catch (Exception e) {
//
//        }
    }

//    @Test
//    public void testHeartbeat() {
//        LOG.info("================================Heartbeat");
//        CryptoClient client = new CryptoClient("10.210.20.61", "default_user", path);
//        try {
//            client.heartbeat();
//        } catch (Exception e) {
//
//        }
//    }

//    @Test
//    public void testReloadCfgFileOtherPath() throws Exception {
//
//        Map<String, Object> map = new HashMap<>();
//        map.put("reload_type", 1);
//        map.put("reload_path", "/opt/infosec/UCypher/crypto/bin");
//        map.put("reload_username", "default_user");
//
//        String jsonString = JSON.toJSONString(map);
//        System.out.println(jsonString);
//        jsonString = jsonString.substring(1, jsonString.length() - 1);
//        System.out.println(jsonString);
//
//        CryptoClient client = new CryptoClient("10.210.20.155", "default_user", path);
//        client.reloadCfgFileOtherPath(jsonString);
//    }

//    @Test
//    public void testInitDevice() throws Exception {
//        String initTime = String.format(Java8DateUtils.getLocalDateTime().atOffset(ZoneOffset.ofHours(8)).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss+08:00")));
//
//        DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
//        String format = String.format(Java8DateUtils.getLocalDateTime().atOffset(ZoneOffset.ofHours(8)).format(formatter));
//
//        Map<String, Object> initinfoMap = new HashMap<>();
//        initinfoMap.put("usedefaultlmk", "false");
//        initinfoMap.put("spk_type", 4);
//        initinfoMap.put("spkek", "1");
//        initinfoMap.put("manager", "admin");
//        initinfoMap.put("managerauthcode", "12345678");
//        initinfoMap.put("inittime", initTime);
//        initinfoMap.put("defaultstoremode", "ext");
//        initinfoMap.put("defaultdoublekeymode", "single");
//        initinfoMap.put("managercert", "cert");
//
//        Map<String, Object> map = new HashMap<>();
//        map.put("type", "use_chsm_spk");
//        map.put("initinfo", initinfoMap);
//
//        String jsonString = JSON.toJSONString(map);
//        System.out.println(jsonString);
//        jsonString = jsonString.substring(1, jsonString.length() - 1);
//        System.out.println(jsonString);
//
//        CryptoClient client = new CryptoClient("10.210.20.155", "admin", path);
//        client.initDevice(jsonString);
//    }

//    @Test
//    public void testTime() {
//        DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
//        String format = String.format(Java8DateUtils.getLocalDateTime().atOffset(ZoneOffset.ofHours(8)).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss+08:00")));
//        System.out.println(format);
//    }


    @Test
    public void testPrimaryKeyHashSM2() throws Exception {
        byte[] hash = CipherUtil.digest("Hello World".getBytes(), "SM3");
        ByteBuffer signature = ByteBuffer.allocate(64);

        CryptoClient client = new CryptoClient("10.210.20.18", "default_user", path);
        client.SDFPrimaryKeySignHashSM2(hash, signature);
        System.out.println(HexFormat.of().formatHex(DataUtil.getDataInByteBuffer(signature)));
        client.SDFPrimaryKeyVerifyHashSM2(hash, DataUtil.getDataInByteBuffer(signature));
        System.out.println(HexFormat.of().formatHex(DataUtil.getDataInByteBuffer(signature)));
    }

    @Test
    public void testPrimaryKeyDataSM2() throws Exception {
        byte[] plainData = "Hello, World".getBytes(StandardCharsets.UTF_8);
        ByteBuffer signature = ByteBuffer.allocate(64);

        CryptoClient client = new CryptoClient("10.210.20.18", "default_user", path);
        client.SDFPrimaryKeySignDataSM2(plainData, signature);
        System.out.println(HexFormat.of().formatHex(DataUtil.getDataInByteBuffer(signature)));
        client.SDFPrimaryKeyVerifyDataSM2(plainData, DataUtil.getDataInByteBuffer(signature));
        System.out.println(HexFormat.of().formatHex(DataUtil.getDataInByteBuffer(signature)));
    }

    @Test
    public void testPrimaryKeyCipherSM2() throws Exception {
        byte[] data = "Hello, World".getBytes(StandardCharsets.UTF_8);

        CryptoClient client = new CryptoClient("10.210.20.18", "default_user", path);
        byte[] encData = client.SDFPrimaryKeyEncryptSM2(data);
        System.out.println(HexFormat.of().formatHex(encData));
        byte[] plainData = client.SDFPrimaryKeyDecryptSM2(encData);
        System.out.println(new String(plainData));
    }

//    @Test
//    public void testIoInfo() throws Exception {
//        CryptoClient client = new CryptoClient("10.210.20.18", "default_user", path);
//        String ioInfo = client.getIoInfo();
//        System.out.println(ioInfo);
//
//        ioInfo = ioInfo.substring(ioInfo.indexOf(":") + 1);
////        System.out.println(ioInfo);
//
//        JSONObject jsonObject = JSON.parseObject(ioInfo);
//        jsonObject.put("maxcpu", 128); //128
//        jsonObject.put("bind_cpu", "true"); // false
//        jsonObject.put("epoll_timeout", 500); // 500
//
//        String jsonString = jsonObject.toJSONString();
//        System.out.println(jsonString);
//
//        client.setIoInfo("\"ServiceIoInfo\":" + JSON.toJSONString(jsonObject));
//
//    }

}
