package org.example.routing;

import com.rabbitmq.client.BuiltinExchangeType;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import org.example.ConnectionUtil;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * @author infosec
 * @since 2024/12/31
 */
public class Producer {

    // 交换机名称
    static final String DIRECT_EXCHANGE_NAME = "direct_exchange";
    // 队列名称
    static final String DIRECT_QUEUE_INSERT = "direct_queue_insert";
    // 队列名称
    static final String DIRECT_QUEUE_UPDATE = "direct_queue_update";

    public static void main(String[] args) throws IOException, TimeoutException {
        Connection connection = ConnectionUtil.getConnection();
        Channel channel = connection.createChannel();

        channel.exchangeDeclare(DIRECT_EXCHANGE_NAME, BuiltinExchangeType.DIRECT);

        channel.queueDeclare(DIRECT_QUEUE_INSERT, true, false, false, null);
        channel.queueDeclare(DIRECT_QUEUE_UPDATE, true, false, false, null);

        channel.queueBind(DIRECT_QUEUE_INSERT, DIRECT_EXCHANGE_NAME, "insert");
        channel.queueBind(DIRECT_QUEUE_UPDATE, DIRECT_EXCHANGE_NAME, "update");

        String message = "新增了商品，路由模式；routing key 为 insert";

        channel.basicPublish(DIRECT_EXCHANGE_NAME, "insert", null, message.getBytes());
        System.out.println("已发送消息：" + message);

        message = "修改了商品，路由模式；routing key 为 update";
        channel.basicPublish(DIRECT_EXCHANGE_NAME, "update", null, message.getBytes());
        System.out.println("已发送消息：" + message);

        channel.close();
        connection.close();
    }

}
