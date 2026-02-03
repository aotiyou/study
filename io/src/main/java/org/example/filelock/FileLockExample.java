package org.example.filelock;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/**
 * @author infosec
 * @since 2025/11/21
 */
public class FileLockExample {

    public static void main(String[] args) {
        RandomAccessFile file = null;
        FileChannel channel = null;
        FileLock lock = null;

        try {
            // 打开文件
            file = new RandomAccessFile("D:\\opt\\infosec\\db\\db.lock", "rw");
            channel = file.getChannel();

            // 获取文件锁，阻塞式锁定
            lock = channel.lock();

            System.out.println("File locked successfully. Performing file operations...");

            // 在这里执行对文件的读取或写入操作
            // 例如，写入文件内容
            file.write("Hello, world!".getBytes());

            // 模拟长时间操作
            Thread.sleep(20000000);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        } finally {
            try {
                // 释放锁
                if (lock != null) {
                    lock.release();
                    System.out.println("File lock released.");
                }

                // 关闭文件通道
                if (channel != null) {
                    channel.close();
                }
                if (file != null) {
                    file.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
