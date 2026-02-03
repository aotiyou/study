package org.example.pool;

import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.io.PrintStream;

@Slf4j
public class Test {
    //连接池配置
    private static final ConnectionPoolConfig config = new ConnectionPoolConfig();
    //创建连接池
    private static final ConnectionPool SOCKET_POOL = new ConnectionPool(config);

    public static void main(String[] args) throws Exception {

        for (int i = 0; i < 100; i++) {
            new Thread(() -> {
                try {
                    SocketConnection connection = SOCKET_POOL.borrowObject();
                    log.info("（使用连接）现在还剩："+SOCKET_POOL.getNumIdle()+"个对象！！！");
                    log.info("（使用连接）已经在使用的对象数量："+SOCKET_POOL.getNumActive());
                    InputStream reader = connection.getReader();
                    PrintStream out = connection.getOut();
                    System.out.println(connection);
                    System.out.println(sendCmd(new PrintStream(out), reader, "ZMNF:IMSI=460016867487331;"));
                    SOCKET_POOL.returnObject(connection);
                    log.info("（释放连接）现在还剩："+SOCKET_POOL.getNumIdle()+"个对象！！！");
                    log.info("（释放连接）已经在使用的对象数量："+SOCKET_POOL.getNumActive());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }

    private static String sendCmd(PrintStream out, InputStream in, String cmd) throws Exception {
        out.println(cmd);
        out.flush();
        return readUntil(in);
    }


    private static String readUntil(InputStream reader) {
        return null;
    }
}
