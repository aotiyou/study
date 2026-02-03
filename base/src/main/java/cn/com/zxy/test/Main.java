package cn.com.zxy.test;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * @author infosec
 * @since 2025/10/21
 */
public class Main {

    protected static void test() {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.put(new byte[13]);
        buffer.put("123".getBytes());
        System.out.println("buffer = " + buffer.getInt());
    }

    @Test
    public void test1() {
        List<String> list = Arrays.asList();
        System.out.println(" = " + String.join(":", list));
    }

    @Test
    public void testListAndMap() {
        List<Map<String, String>> list = new ArrayList<>();
        Map<String, String> map = new HashMap<>();
        map.put("test", "test");
        list.add(map);
        setMap(list);

        list.forEach(item -> {
            item.forEach((key, value) -> {
                System.out.println(key + " = " + value);
            });
        });
    }

    private void setMap(List<Map<String, String>> list) {
        Map<String, String> map = list.get(0);
        map.put("test", "tes111");
    }

    @Test
    public void testLongToBytes() {
        long l = 555555555L;
        byte[] array = ByteBuffer.allocate(Long.BYTES).putLong(l).array();
        System.out.println("HexFormat.of().formatHex(array) = " + HexFormat.of().formatHex(array));

        System.out.println("HexFormat.of().formatHex(long2Byte(l)) = " + HexFormat.of().formatHex(long2Byte(l)));
    }

    private static byte[] long2Byte(long i) {
        byte[] bs = new byte[8];
        bs[7] = (byte) (i & 0xff);
        bs[6] = (byte) (i >>> 8 & 0xff);
        bs[5] = (byte) (i >>> 16 & 0xff);
        bs[4] = (byte) (i >>> 24 & 0xff);

        bs[3] = (byte) (i >>> 32 & 0xff);
        bs[2] = (byte) (i >>> 40 & 0xff);
        bs[1] = (byte) (i >>> 48 & 0xff);
        bs[0] = (byte) (i >>> 56 & 0xff);

        return bs;
    }


    @Test
    public void testArr() {
        String[][] arr = {{"aaa"}, {"1", "2"}};
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr[i].length; j++) {
                System.out.println("j = " + arr[i][j]);
            }
        }
    }

    @Test
    public void testDate() throws ParseException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String format = dateFormat.format(new Date(System.currentTimeMillis()));

        System.out.println("date = " + format);
    }

    @Test
    public void testList() {
        int[] arr = new int[]{32, 64};
        boolean contains = Arrays.asList(arr).contains(32);
        System.out.println("contains = " + contains);
    }

    @Test
    public void testCharacters() {
        char ch = 'A';
        int ascii = (int) ch;
        System.out.println("ascii = " + ascii);

        // UTF-8: [-28, -70, -116, -28, -72, -128]
        // GBK: [-74, -2, -46, -69]
        String plain = "二一";
        System.out.println("plain = " + Arrays.toString(plain.getBytes(Charset.forName("UTF-8"))));

        // UTF-8: [-28, -72, -128, -28, -70, -116, -28, -72, -119, -27, -101, -101, -28, -70, -108]
        // GBK:  [-46, -69, -74, -2, -56, -3, -53, -60, -50, -27]
        String plain2 = "一二三四五";
        System.out.println("plain2 = " + Arrays.toString(plain2.getBytes(Charset.forName("UTF-8"))));
    }

}
