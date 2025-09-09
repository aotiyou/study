package org.example.nio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * @author infosec
 * @since 2025/1/10
 */
public class M04_SocketServer {

    private final static Logger logger = LoggerFactory.getLogger(M04_SocketServer.class);


    public static void main(String[] args) {
        int port = 8080;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
//            serverSocket.setSoTimeout(15000); // 10 秒等待客户端连接

            logger.info("服务器已启动，等待客户端连接...");
            try {
                Socket clientSocket = serverSocket.accept();
                logger.info("客户端连接成功：{}", clientSocket.getInetAddress());

//                clientSocket.setSoTimeout(5000); // 5 秒读取超时
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                     PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    String message = reader.readLine(); // 阻塞读取消息
                    logger.info("收到客户端消息：{}", message);

                    try {
                        Thread.sleep(4000);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    logger.info("消息已收到：{}", message);

                    writer.println("消息已收到：" + message); // 发送响应
                } catch (SocketTimeoutException e) {
                    logger.error("读取数据超时：{}", e.getMessage(), e);
                }
            } catch (SocketTimeoutException e) {
                logger.error("等待客户端连接超时：{}", e.getMessage(), e);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
