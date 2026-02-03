package cn.com.zxy.springboot.dto;

import lombok.Data;

import java.util.Map;

/**
 * @author infosec
 * @since 2025/11/18
 */
@Data
public class TaskDTO {

    private String taskId;

    private String result;

    private String errCode;

    private String errMessage;

    private Map<String, Object> data;

    private long timestamp;

    private String nonce;

    private String serviceip;

    private String serviceport;

}
