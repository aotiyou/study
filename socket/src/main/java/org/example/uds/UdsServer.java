package org.example.uds;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;

public class UdsServer {

    private static final String SOCKET_PATH = "/tmp/java-uds-demo.sock";

    public static void main(String[] args) throws Exception {
        Path socketFile = Path.of(SOCKET_PATH);
        Files.deleteIfExists(socketFile);

        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(socketFile);

        try (ServerSocketChannel serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            serverChannel.bind(address);
            System.out.println("[UdsServer] 监听中: " + SOCKET_PATH);

            while (true) {
                SocketChannel clientChannel = serverChannel.accept();
                System.out.println("[UdsServer] 客户端连接");

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(clientChannel.socket().getInputStream(), "UTF-8"));
                PrintWriter out = new PrintWriter(clientChannel.socket().getOutputStream(), true);

                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    System.out.println("[UdsServer] 收到: " + inputLine);

                    if ("bye".equalsIgnoreCase(inputLine)) {
                        out.println("再见！");
                        break;
                    }

                    out.println("UDS服务器回复: [" + inputLine + "]");
                }

                clientChannel.close();
                System.out.println("[UdsServer] 客户端断开");
            }
        } finally {
            Files.deleteIfExists(socketFile);
        }
    }
}
