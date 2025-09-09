package org.example;

import org.junit.Test;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * @author infosec
 * @since 2025/2/14
 */
public class ByteTest {

    @Test
    public void int2Byte() {
        int i = 4096;
        // 大端序（Big-Endian） 是 最高字节在前
        byte[] bytes = new byte[]{
                (byte) (i >> 24),   // 最高位
                (byte) (i >> 16),
                (byte) (i >> 8),
                (byte) i            // 最低位
        };
        System.out.println(HexFormat.of().formatHex(bytes));

        int i1 = (bytes[0] & 0xFF) << 24 | (bytes[1] & 0xFF) << 16 | (bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF);
        System.out.println(i1);
    }

    @Test
    public void testTwoDimensionalByteArray() {
        byte[] bytes = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[][] bytes2 = new byte[][]{
                Arrays.copyOfRange(bytes, 0, bytes.length),
                {0x05, 0x06, 0x07, 0x08},
        };

        System.out.println(HexFormat.of().formatHex(bytes2[0]));
        System.out.println(HexFormat.of().formatHex(bytes2[1]));
    }

    @Test
    public void testChangeInt() {
        int i = 0;
        chagngInt(i);
        System.out.println(i);
    }

    public static void chagngInt(int i) {
        i = 10;
    }

    @Test
    public void convertIntToByte() {
        int i = 10;
        byte b = (byte) i;
        System.out.println(b);

        byte[] a = {59};
        System.out.println("a = " + Arrays.toString(a));
    }


}
