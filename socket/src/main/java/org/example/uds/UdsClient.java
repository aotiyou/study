package org.example.uds;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.util.Scanner;

public class UdsClient {

    private static final String SOCKET_PATH = "/tmp/java-uds-demo.sock";

    public static void main(String[] args) throws Exception {
        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(Path.of(SOCKET_PATH));

        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.connect(address);
            System.out.println("[UdsClient] 已连接到 UDS: " + SOCKET_PATH);

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(channel.socket().getInputStream(), "UTF-8"));
            PrintWriter out = new PrintWriter(channel.socket().getOutputStream(), true);
            Scanner scanner = new Scanner(System.in);

            Thread readThread = new Thread(() -> {
                try {
                    String serverMsg;
                    while ((serverMsg = in.readLine()) != null) {
                        System.out.println("[UdsClient] " + serverMsg);
                    }
                } catch (Exception e) {
                    System.out.println("[UdsClient] 与服务器断开连接");
                }
            });
            readThread.setDaemon(true);
            readThread.start();

            System.out.println("[UdsClient] 输入消息（输入 bye 退出）:");
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                out.println(line);
                if ("bye".equalsIgnoreCase(line)) {
                    break;
                }
            }
        }
    }
}
