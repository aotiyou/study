package org.example.aio;

import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.CompletionHandler;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M05_CompletionHandler {

    class Attachment {

        public Path path;
        public ByteBuffer buffer;
        public AsynchronousFileChannel asyncChannel;
        public int count = 10;

        public synchronized void close() {
            System.out.println("count: " + count);
            if (count-- <= 0) {
                try {
                    this.asyncChannel.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    class WriteHandler implements CompletionHandler<Integer, Attachment> {

        @Override
        public void completed(Integer result, Attachment attachment) {
            System.out.format("%s bytes written to %s\n", result, attachment.path.toAbsolutePath());
            attachment.close();
        }

        @Override
        public void failed(Throwable exc, Attachment attachment) {
            System.out.println(exc.getMessage());
            attachment.close();
        }
    }

    @Test
    public void testCompletionHandler() {

        Path path = Paths.get("D:\\tmp.dat");
        AsynchronousFileChannel afc = null;
        int length = 11;

        try {
            afc = AsynchronousFileChannel.open(path, WRITE, CREATE);

            ByteBuffer buf = ByteBuffer.allocate(1024 * 1024);
            buf.clear();

            for (int i = 0; i < length; i++) {
                buf.put((byte) 1);
            }
            buf.flip();
            buf.mark();

            Attachment attach = new Attachment();
            attach.path = path;
            attach.buffer = buf;
            attach.asyncChannel = afc;

            WriteHandler handler = new WriteHandler();
            long start = System.currentTimeMillis();
            for (int i = 0; i < length; i++) {
                buf.reset();
                afc.write(buf, i * 1024 * 1024, attach, handler);
            }

            System.out.println("写入时间:" + (System.currentTimeMillis() - start) + "ms");

        } catch (IOException e) {
            e.printStackTrace();
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
