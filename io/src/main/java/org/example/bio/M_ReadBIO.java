package org.example.bio;

import org.junit.Test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M_ReadBIO {

    /**
     * 读取时间:695ms
     */
    @Test
    public void testReadFromFileByBIO1() {

        File tmp = new File("D:\\tmp.dat");
        FileInputStream is = null;
        try {
            is = new FileInputStream(tmp);
            long start = System.currentTimeMillis();
            while (is.read() > -1) {

            }
            System.out.println("读取时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 读取时间:1ms
     */
    @Test
    public void testReadFromFileByBIO2() {
        File tmp = new File("D:\\tmp.dat");
        FileInputStream is = null;
        try {
            is = new FileInputStream(tmp);

            byte[] buf = new byte[1024 * 1024];

            long start = System.currentTimeMillis();
            while (is.read(buf) > -1) {

            }
            System.out.println("读取时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 读取时间:18ms
     */
    @Test
    public void testReadFromFileByBIO3() {
        File tmp = new File("D:\\tmp.dat");
        InputStream is = null;
        try {
            is = new BufferedInputStream(new FileInputStream(tmp), 1024 * 1024);

            long start = System.currentTimeMillis();
            while (is.read() > -1) {

            }
            System.out.println("读取时间:" + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
