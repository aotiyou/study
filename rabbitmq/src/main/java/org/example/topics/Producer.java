package org.example.topics;

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

    static final String TOPIC_EXCHANGE = "topic_exchange";
    static final String TOPIC_QUEUE_1 = "topic_queue_1";
    static final String TOPIC_QUEUE_2 = "topic_queue_2";

    public static void main(String[] args) throws IOException, TimeoutException {
        Connection connection = ConnectionUtil.getConnection();
        Channel channel = connection.createChannel();

        channel.exchangeDeclare(TOPIC_EXCHANGE, BuiltinExchangeType.TOPIC);

        String message = "新增了商品；topic模式：routing key 为 item.insert";
        channel.basicPublish(TOPIC_EXCHANGE, "item.insert", null, message.getBytes());

        message = "修改了商品；topic模式：routing key 为 item.update";
        channel.basicPublish(TOPIC_EXCHANGE, "item.update", null, message.getBytes());

        message = "删除了商品；topic模式：routing key 为 item.delete";
        channel.basicPublish(TOPIC_EXCHANGE, "item.delete", null, message.getBytes());

        channel.close();
        connection.close();

    }


}
