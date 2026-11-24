package org.example.simple;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class SimpleServer {

    private static final int PORT = 8888;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("[SimpleServer] 启动成功，监听端口: " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[SimpleServer] 客户端连接: " + clientSocket.getRemoteSocketAddress());

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream(), "UTF-8"));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    System.out.println("[SimpleServer] 收到消息: " + inputLine);

                    if ("bye".equalsIgnoreCase(inputLine)) {
                        out.println("再见！");
                        break;
                    }

                    out.println("服务器回复: [" + inputLine + "]");
                }

                clientSocket.close();
                System.out.println("[SimpleServer] 客户端断开连接");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
