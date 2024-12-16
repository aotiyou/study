package org.example.bio;

import org.junit.Test;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * 参考资料：https://jiges.github.io/2018/03/01/BIO%E3%80%81NIO%E4%B8%8EAIO-%E4%B8%80/
 */
public class M_WriteBIO {

    /**
     * 写入时间:1226ms
     */
    @Test
    public void testWriteAFileByBIO() {
        long length = 1 * 1024 * 1024;
        byte b = 1;
        File tmp = new File("D:\\tmp.dat");
        FileOutputStream output = null;
        try {
            if (!tmp.exists()) {
                tmp.createNewFile();
            }
            output = new FileOutputStream(tmp);
            long start = System.currentTimeMillis();
            while (length -- > 0) {
                output.write(b);
            }
            System.out.println("写入时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 写入时间:1ms
     */
    @Test
    public void testWriteAFileByBIO2() {
        long length = 1;
        File tmp = new File("D:\\tmp.dat");
        FileOutputStream output = null;
        try {
            if (!tmp.exists()) {
                tmp.createNewFile();
            }
            output = new FileOutputStream(tmp);

            byte[] byteArr = new byte[1024 * 1024];
            // 一次写入1M的内容
            for (int i = 0; i < byteArr.length; i++) {
                byteArr[i] = 1;
            }

            long start = System.currentTimeMillis();
            while (length -- > 0) {
                output.write(byteArr);
            }
            System.out.println("写入时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 写入时间:17ms
     */
    @Test
    public void testWriteAFileByBIO3() {
        long length = 1 * 1024 * 1024;
        File tmp = new File("D:\\tmp.dat");
        OutputStream output = null;
        try {
            if (!tmp.exists()) {
                tmp.createNewFile();
            }
            //一次写入1M的内容
            output = new BufferedOutputStream(new FileOutputStream(tmp), 1024 * 1024);

            long start = System.currentTimeMillis();
            while (length -- > 0) {
                output.write(1);
            }
            System.out.println("写入时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
