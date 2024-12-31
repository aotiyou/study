package org.example;

import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * @author infosec
 * @since 2024/12/31
 */
public class ConnectionUtil {

    public static Connection getConnection() throws IOException, TimeoutException {
        //创建连接工厂
        ConnectionFactory connectionFactory = new ConnectionFactory();
        //设置主机地址
        connectionFactory.setHost("localhost");
        //设置端口号
        connectionFactory.setPort(5672);
        //设置虚拟主机
        connectionFactory.setVirtualHost("/admin");
        //设置用户名
        connectionFactory.setUsername("admin");
        //设置密码
        connectionFactory.setPassword("admin");
        //创建连接
        Connection connection = connectionFactory.newConnection();
        return connection;
    }

}
