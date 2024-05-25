package org.example.java;


import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class SocketServer extends WebSocketServer {

    public SocketServer(int port) throws UnknownHostException {
        super(new InetSocketAddress(port));
    }

    public SocketServer(InetSocketAddress address) {
        super(address);
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        conn.send("Welcome to the server!"); // This method sends a message to the new client
        broadcast("new connection: " + handshake
                .getResourceDescriptor()); // This method sends a message to all clients connected
        System.out.println(
                conn.getRemoteSocketAddress().getAddress().getHostAddress() + " entered the room!");

    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        broadcast(conn + " has left the room!");
        System.out.println(conn + " has left the room!");

    }

    @Override
    public void onMessage(WebSocket conn, String message) {


        String sourceFilePath = "D:\\logs\\hsm\\debug_log\\2024-01-19\\debug_log_run_0.log"; // 文件路径

        String targetFilePath = "D:\\logs\\hsm\\debug_log\\2024-01-19\\debug_log_run_1.log"; // 文件B的路径


        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(sourceFilePath));
             BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(targetFilePath))) {

            // 逐行读取文件A的内容，并写入文件B
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                bufferedWriter.write(line);
                // 写入一个新行符，以保持原始文件的格式
                bufferedWriter.newLine();
                broadcast(line + "\n");
            }

            System.out.println("文件内容已从 " + sourceFilePath + " 复制到 " + targetFilePath);

        } catch (IOException e) {
            e.printStackTrace();
        }

//        Path path = Paths.get(filePath);
//        if (Files.exists(path) && Files.isReadable(path)) {
//            try (BufferedReader reader = Files.newBufferedReader(path)) {
//                String line;
//                while ((line = reader.readLine()) != null) {
//                    broadcast(line + "\n");
//                }
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        }


        broadcast(message);
        System.out.println(conn + ": " + message);
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        ex.printStackTrace();
        if (conn != null) {
            // some errors like port binding failed may not be assignable to a specific
            // websocket
        }

    }

    @Override
    public void onStart() {
        System.out.println("Server started!");
        setConnectionLostTimeout(0);
        setConnectionLostTimeout(100);

    }

    private void sendFile(String filename) throws IOException {

    }


    public static void main(String[] args) throws InterruptedException, IOException {
        int port = 8887; // 843 flash policy port

        SocketServer s = new SocketServer(port);
        s.start();
        System.out.println("ChatServer started on port: " + s.getPort());

        BufferedReader sysin = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            String in = sysin.readLine();
            s.broadcast(in);
            if (in.equals("exit")) {
                s.stop(1000);
                break;
            }
        }
    }


}


