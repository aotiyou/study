package org.example.simple;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class SimpleClient {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 8888;

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT);
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(socket.getInputStream(), "UTF-8"));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             Scanner scanner = new Scanner(System.in)) {

            System.out.println("[SimpleClient] 已连接到服务器 " + HOST + ":" + PORT);

            Thread readThread = new Thread(() -> {
                try {
                    String serverMsg;
                    while ((serverMsg = in.readLine()) != null) {
                        System.out.println("[SimpleClient] " + serverMsg);
                    }
                } catch (Exception e) {
                    System.out.println("[SimpleClient] 与服务器断开连接");
                }
            });
            readThread.setDaemon(true);
            readThread.start();

            System.out.println("[SimpleClient] 输入消息（输入 bye 退出）:");
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                out.println(line);
                if ("bye".equalsIgnoreCase(line)) {
                    break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
