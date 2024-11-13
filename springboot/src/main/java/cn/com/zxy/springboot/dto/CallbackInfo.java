package cn.com.zxy.springboot.dto;

import lombok.Data;

/**
 * @author infosec
 * @since 2024/11/13
 */
@Data
public class CallbackInfo {

    private String requestId;

    private Integer status;

    private String timestamp;

    private String data;

    private String extMessage;


}
