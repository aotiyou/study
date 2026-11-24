package org.client;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Client {
    private static int port = 9999;
//    private static String host = "192.168.52.131";
	private static String host = "127.0.0.1";

    public static SimpleDateFormat sdf = new SimpleDateFormat(
            "yy-MM-dd HH:mm:ss.SSS");

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket();
//		CASE 1 : default setting 关闭SO_LINGER，close()方法会立即返回，底层系统会在后台继续发送数据，直到发送完成或者发生错误才会真正关闭连接。
        socket.setSoLinger(false, 0);
//		CASE 2 : 开启SO_LINGER，设置为0，close()方法会立即返回，并且底层系统会立即丢弃未发送的数据，直接关闭连接。
//		socket.setSoLinger(true, 0);
//		CASE 3 : 开启SO_LINGER，设置为1，close()方法会阻塞1秒钟，等待底层系统发送数据完成或者发生错误，如果在1秒钟内发送完成或者发生错误，连接会正常关闭；如果超过1秒钟还没有发送完成，连接会被强制关闭，未发送的数据会被丢弃。
//		socket.setSoLinger(true, 1);
        SocketAddress address = new InetSocketAddress(
                Client.host, Client.port);
        socket.connect(address);

        OutputStream output = socket.getOutputStream();
        StringBuilder strB = new StringBuilder();
        for(int i = 0 ; i < 10000000 ; i++ ){
            strB.append("a");
        }
        byte[] request = strB.toString().getBytes("utf-8");
        System.out.println("Client before write : " + sdf.format(new Date()));
        output.write(request);
        System.out.println("Client after write : " + sdf.format(new Date()));
        socket.close();
        System.out.println("Client after close : " + sdf.format(new Date()));
    }
}
