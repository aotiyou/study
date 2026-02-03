package org.example.filelock;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/**
 * @author infosec
 * @since 2025/11/21
 */
public class TryLockExample {

    public static void main(String[] args) {
        RandomAccessFile file = null;
        FileChannel channel = null;
        FileLock lock = null;

        try {
            // 打开文件
            file = new RandomAccessFile("D:\\opt\\infosec\\db\\db.lock", "rw");
            channel = file.getChannel();

            // 非阻塞的尝试获取文件锁
            lock = channel.tryLock();

            if (lock != null) {
                System.out.println("File locked successfully.");

                // 在这里执行文件操作
                file.write("Hello, non-blocking world!".getBytes());
            } else {
                System.out.println("Could not acquire file lock.");
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (lock != null) {
                    lock.release();
                    System.out.println("File lock released.");
                }
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
