package org.example.stomp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.stereotype.Controller;

/**
 * @author infosec
 * @since 2024/3/25
 */
@Controller
public class WSController {

    @Autowired
    private SimpMessagingTemplate simpMessagingTemplate;

    @MessageMapping("/greeting")
    @SendToUser("/queue/serverReply")
    public String greating(@Payload String data) {
        System.out.println("received greeting: " + data);
        String msg = "server replys: " + data;
        return msg;
    }

    @MessageMapping("/shout")
    public void userShout(Shout shout) {
        //String name = principal.getName();
        String message = shout.getMessage();
        System.out.println("收到的消息是：" + message);
        simpMessagingTemplate.convertAndSend("/queue/notifications", shout);

    }

}
