package org.example.workQueues;

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

    static final String QUEUE_NAME = "work_queue";

    public static void main(String[] args) throws IOException, TimeoutException {
        Connection connection = ConnectionUtil.getConnection();
        // 创建频道
        Channel channel = connection.createChannel();
        // 声明（创建）队列
        /**
         * 参数1：队列名称
         * 参数2：是否持久化队列
         * 参数3：队列是否独占本次连接
         * 参数4：队列不再使用时是否自动删除队列
         * 参数5：队列其他参数
         */
        channel.queueDeclare(QUEUE_NAME, true, false, false, null);

        for (int i = 0; i < 30; i++) {
            // 要发送的信息
            String message = "hi man! work queue" + i;
            channel.basicPublish("", QUEUE_NAME, null, message.getBytes());
            System.out.println("已发送消息：" + message);
        }

        // 关闭资源
        channel.close();
        connection.close();
    }

}
