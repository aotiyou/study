package cn.com.infosec.crypto.algithm;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Hmac算法就是一种基于密钥得消息认证码算法，它的全称是Hash-based Message Authentication Code, 是一种更安全得消息摘要算法。
 * Hmac算法总是和某种哈希算法配合起来用的。例如：我们使用MD5算法，对应的就是HmacMD5算法，它相当于“加盐”的MD5
 *
 * 有如下好处：
 *  HmacMD5使用的key长度是64字节，更安全
 *  Hmac是标准算法，同样适用于SHA-1等其他哈希算法
 *  Hmac输出和原有的哈希算法长度一样
 *
 * @author infosec
 * @since  2024/8/20
 */
public class HmacMain {

    /**
     * 示例：HmacMD5算法
     *
     * @throws Exception
     */
    @Test
    public void genHmacHash() throws Exception {
        // 1.通过名称HmacMD5获取KeyGenerator实例
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
        // 2.通过KeyGenerator创建一个SecretKey实例
        SecretKey key = keyGen.generateKey();
        byte[] keyEncoded = key.getEncoded();
        System.out.println(HexFormat.of().formatHex(keyEncoded));

        // 3.通过名称HmacMD5，获取Mac实例
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);
        // 对Mac实例反复调用update(byte[])输入数据
        mac.update("hello world".getBytes(StandardCharsets.UTF_8));
        // 4. 调用Mac实例的doFinal()获取最终的哈希值
        byte[] result = mac.doFinal();
        System.out.println(HexFormat.of().formatHex(result));
    }

    /**
     * 示例：验证Hmac哈希
     *
     * @throws Exception
     */
    @Test
    public void verifyHmacHash() throws Exception {
        byte[] hkey = HexFormat.of().parseHex(
                "b648ee779d658c420420d86291ec70f5" +
                        "cf97521c740330972697a8fad0b55f5c" +
                        "5a7924e4afa99d8c5883e07d7c3f9ed0" +
                        "76aa544d25ed2f5ceea59dcc122babc8");
        SecretKeySpec key = new SecretKeySpec(hkey, "HmacMD5");
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);
        mac.update("HelloWorld".getBytes(StandardCharsets.UTF_8));
        byte[] result = mac.doFinal();
        System.out.println(HexFormat.of().formatHex(result));

    }
}
