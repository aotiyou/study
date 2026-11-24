package org.example.chat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class ChatServer {

    private static final int PORT = 7777;
    private static final ConcurrentHashMap<String, PrintWriter> clients = new ConcurrentHashMap<>();
    private static final AtomicInteger clientCounter = new AtomicInteger(0);

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("[ChatServer] 聊天服务器启动，监听端口: " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                String clientId = "用户" + clientCounter.incrementAndGet();
                System.out.println("[ChatServer] " + clientId + " 加入聊天室");
                new ClientHandler(clientId, clientSocket).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void broadcast(String message) {
        System.out.println("[ChatServer] 广播: " + message);
        clients.forEach((id, writer) -> {
            try {
                writer.println(message);
            } catch (Exception e) {
                clients.remove(id);
            }
        });
    }

    private static class ClientHandler extends Thread {
        private final String clientId;
        private final Socket socket;

        ClientHandler(String clientId, Socket socket) {
            this.clientId = clientId;
            this.socket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                clients.put(clientId, out);
                out.println("欢迎来到聊天室！你的ID是: " + clientId);
                broadcast("[系统] " + clientId + " 加入了聊天室，当前在线: " + clients.size() + " 人");

                String message;
                while ((message = in.readLine()) != null) {
                    if ("bye".equalsIgnoreCase(message.trim())) {
                        break;
                    }
                    broadcast("[" + clientId + "] " + message);
                }

            } catch (Exception e) {
                System.out.println("[ChatServer] " + clientId + " 连接异常");
            } finally {
                clients.remove(clientId);
                broadcast("[系统] " + clientId + " 离开了聊天室，当前在线: " + clients.size() + " 人");
                try {
                    socket.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
