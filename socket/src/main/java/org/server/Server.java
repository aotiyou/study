package org.server;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Server {
	private static int queueSize = 10;
	private static int port = 9999;

	public static SimpleDateFormat sdf = new SimpleDateFormat(
			"yy-MM-dd HH:mm:ss.SSS");

	public static void main(String[] args) throws Exception {
		ServerSocket serverSocket = new ServerSocket();
		serverSocket.setReuseAddress(true);
		serverSocket.setReceiveBufferSize(128*1024);
		serverSocket.bind(new InetSocketAddress(Server.port),
				Server.queueSize);

		Socket socket = null;
		while(true){
			socket = serverSocket.accept();
			InputStream input = socket.getInputStream();
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int length = -1;
			Thread.sleep(10*1000);
			System.out.println("Server before read : " + sdf.format(new Date()));
			while((length = input.read(buffer)) != -1){
				output.write(buffer, 0, length);
			}
			System.out.println("Server after read : " + sdf.format(new Date()));
			String req = new String(output.toByteArray(), "utf-8");
			System.out.println(req.length());

			socket.close();
		}
	}
}
