package org.example.nio;

import org.junit.Test;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M02_ReadNIO {

    /**
     * 读取时间:1ms
     */
    @Test
    public void testReadFileByNIO() {

        FileChannel inChannel = null;

        try {
            RandomAccessFile aFile = new RandomAccessFile("D:\\tmp.dat", "rw");
            inChannel = aFile.getChannel();

            ByteBuffer buf = ByteBuffer.allocate(1024 * 1024);

            long start = System.currentTimeMillis();
            while (inChannel.read(buf) > -1) {
                // 从buf中读取数据
                buf.clear();
            }
            System.out.println("读取时间:" + (System.currentTimeMillis() - start) + "ms");
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
