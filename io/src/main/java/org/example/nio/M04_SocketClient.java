package org.example.nio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * @author infosec
 * @since 2025/1/10
 */
public class M04_SocketClient {

    private final static Logger logger = LoggerFactory.getLogger(M04_SocketClient.class);


    public static void main(String[] args) {
        String serverAddress = "127.0.0.1";
        int serverPort = 8080;

//        for (int i = 0; i < 100; i++) {
//            final int finalI = i;
            new Thread(() -> {
                try (Socket socket = new Socket()) {
                    // 设置连接和读取超时
//                    socket.connect(new InetSocketAddress(serverAddress, serverPort), 5000); // 连接超时 5 秒
                    socket.connect(new InetSocketAddress(serverAddress, serverPort));
                    logger.info("正在尝试连接到服务器: {}", serverAddress + ":" + serverPort);
                    try {
                        Thread.sleep(100000);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                    socket.setSoTimeout(5000); // 读取超时 5 秒

                    logger.info("成功连接到服务器: {}", serverAddress + ":" + serverPort);

                    // 发送消息到服务器
                    PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
                    writer.println("Hello, Server! thread = " + Thread.currentThread().getName());

                    // 接收服务器的响应
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String response = reader.readLine();
                    logger.info("服务器响应: {}", response);

                } catch (SocketTimeoutException e) {
                    logger.error("操作超时: {}", e.getMessage(), e);
                } catch (IOException e) {
                    logger.error("连接超时：{}", e.getMessage(), e);
                }

            }).start();
//        }
    }

}
