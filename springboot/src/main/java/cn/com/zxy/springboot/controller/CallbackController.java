package cn.com.zxy.springboot.controller;

import cn.com.zxy.springboot.dto.CallbackInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author infosec
 * @since 2024/11/13
 */
@Slf4j
@RestController
public class CallbackController {

    @PostMapping("callback")
    public ResponseEntity callback(@RequestBody CallbackInfo callbackInfo) {
        log.info("callbackInfo: {}", callbackInfo);
        return ResponseEntity.ok("回调处理成功");
    }

}
