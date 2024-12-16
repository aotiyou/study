package org.example.aio;

import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M04_Future {

    /**
     * 写入时间:1ms
     */
    @Test
    public void test() {

        Path path = Paths.get("D:\\tmp.dat");
        AsynchronousFileChannel afc = null;
        int length = 11;

        try {
            afc = AsynchronousFileChannel.open(path, WRITE, CREATE);
            ArrayList<Future<Integer>> results = new ArrayList<>();

            ByteBuffer buf = ByteBuffer.allocate(1024 * 1024);
            buf.clear();

            for (int i = 0; i < length; i++) {
                buf.put((byte) 1);
            }
            buf.flip();
            buf.mark();

            long start = System.currentTimeMillis();
            for (int i = 0; i < length; i++) {
                buf.reset();
                results.add(afc.write(buf, i * 1024 * 1024));
            }

            for (Future<Integer> future : results) {
                future.get();
            }

            System.out.println("写入时间:" + (System.currentTimeMillis() - start) + "ms");

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            if (afc != null) {
                try {
                    afc.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

}
