package org.example.nio;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Set;

/**
 * @author infosec
 * @since 2024/12/16
 */
public class M03_IOMultiplexing {

    public static void main(String[] args) throws IOException {
        startServer();
        startClient();
    }

    public static void startServer() throws IOException {
        Selector selector = Selector.open();
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.bind(new InetSocketAddress(8000));
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

        new Thread(() -> {
            try {

                while (true) {
                    // select会阻塞知道至少一个已注册的通道准备号进行I/O操作，或者当前线程被中断
                    int readyChannel = selector.select(1000);// 等待1s或直到有事件就绪
                    if (readyChannel == 0) continue; // 如果没有就绪的通道，则继续下一次循环

                    // 当selector.select() 返回时，通过所selectedKeys() 获取已就绪的通道集合并遍历他们
                    // 在处理完一个键后，通过iterator.remove() 将其从集合中移除，防止下次循环再次处理
                    Set<SelectionKey> selectionKeys = selector.selectedKeys();
                    Iterator<SelectionKey> iterator = selectionKeys.iterator();
                    while (iterator.hasNext()) {
                        SelectionKey key = iterator.next();
                        iterator.remove();

                        if (key.isAcceptable()) {
                            ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
                            SocketChannel socketChannel = serverChannel.accept();
                            socketChannel.configureBlocking(false);

                            String message = "Hi, I'm server";
                            socketChannel.write(Charset.defaultCharset().encode(message));

                            socketChannel.register(selector, SelectionKey.OP_READ);
                            System.out.println("Accepted connection from " + socketChannel.getRemoteAddress());

                        } else if (key.isReadable()) {
                            SocketChannel socketChannel = (SocketChannel) key.channel();
                            ByteBuffer buf = ByteBuffer.allocate(1024);
                            int len = socketChannel.read(buf);
                            if (len > 0) {
                                buf.flip();
                                System.out.println("收到客户端消息：" + Charset.defaultCharset().decode(buf));
                            }
                        }
                    }
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

        }).start();
    }

    private static void startClient() throws IOException {
        Selector selector = Selector.open();
        SocketChannel socketChannel = SocketChannel.open(new InetSocketAddress("127.0.0.1", 8000));
        socketChannel.configureBlocking(false);
        socketChannel.register(selector, SelectionKey.OP_WRITE);

        new Thread(() -> {

            try {

                while (true) {
                    // select 会阻塞直到至少有一个已注册的同胞准备进行I/O操作，或者当前线程被中断
                    selector.select(1000);
                    Set<SelectionKey> selectionKeys = selector.selectedKeys();
                    Iterator<SelectionKey> iterator = selectionKeys.iterator();
                    while (iterator.hasNext()) {
                        SelectionKey key = iterator.next();
                        iterator.remove();
                        if (key.isWritable()) {
                            SocketChannel clientChannel = (SocketChannel) key.channel();
                            String message = "Hi, I'm client";
                            clientChannel.write(Charset.defaultCharset().encode(message));
                            clientChannel.register(selector, SelectionKey.OP_READ);
                        } else if (key.isReadable()) {
                            SocketChannel clientChannel = (SocketChannel) key.channel();
                            ByteBuffer buf = ByteBuffer.allocate(1024);
                            int len = clientChannel.read(buf);
                            if (len > 0) {
                                buf.flip();
                                System.out.println("收到服务端消息：" + Charset.defaultCharset().decode(buf));
                            }
                        }
                    }

                }

            } catch (IOException e) {
                throw new RuntimeException(e);
            }


        }).start();
    }

}
