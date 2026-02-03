package cn.com.zxy.test2;

import cn.com.zxy.test.Main;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * @author infosec
 * @since 2025/10/21
 */
public class Test2 extends Main {

    public static void main(String[] args) {
//        byte[] array = ByteBuffer.allocate(4).putInt(20).array();
//        System.out.println("array = " + new BigInteger(1, array).toString(16));

        ByteBuffer buffer = ByteBuffer.allocate(100);
//        buffer.put(new byte[12]);
        buffer.putInt(1);

        System.out.println("position = " + buffer.position());
        System.out.println("limit = " + buffer.limit());
        buffer.flip();
        System.out.println("limit = " + buffer.limit());
        System.out.println("position = " + buffer.position());

        System.out.println(buffer.get(new byte[buffer.limit()]));
        System.out.println("position = " + buffer.position());
//        buffer.flip();
//        System.out.println(buffer.getInt(12));
//        System.out.println("HexFormat.of().formatHex(buffer.get(12)) = " + HexFormat.of().formatHex(buffer.get(12)));

//        int[] ints = splitData(2, 4);
//        for (int in : ints) {
//            System.out.println("in = " + in);
//        }
//        System.out.println("ints = " + ints.length);


    }

    private static int[] splitData(int length, int maxChunkSize) {
        int chunkCount = (length + maxChunkSize - 1) / maxChunkSize;
        int[] chunks = new int[chunkCount];
        Arrays.fill(chunks, 0, chunkCount - 1, maxChunkSize);
        chunks[chunkCount - 1] = length - (chunkCount - 1) * maxChunkSize;
        return chunks;
    }

}
