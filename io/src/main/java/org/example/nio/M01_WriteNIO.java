package org.example.nio;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M01_WriteNIO {

    /**
     * 写入时间:1ms
     */
    @Test
    public void testWriteFileByNIO() {

        File tmp = new File("D:\\tmp.dat");
        int length = 1;
        FileChannel inChannel = null;
        try {
            if(!tmp.exists()) {
                tmp.createNewFile();
            }

            RandomAccessFile aFile = new RandomAccessFile(tmp, "rw");
            inChannel = aFile.getChannel();
            // 常见一个ByteBuffer，默认是写模式
            ByteBuffer buf = ByteBuffer.allocate(1024 * 1024);
            // 将buffer的position设为0，limit设为capacity
            buf.clear();
            for (int i = 0; i < 1024 * 1024; i++) {
                buf.put((byte) 1);
            }
            // 转换读模式将limit设为原来的position，position设为0
            buf.flip();
            buf.mark();

            long start = System.currentTimeMillis();
            for (int i = 0; i < length; i++) {
                buf.reset();
                while (buf.hasRemaining()) {
                    inChannel.write(buf);
                }
            }
            System.out.println("写入时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {

            if (inChannel != null) {
                try {
                    inChannel.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
