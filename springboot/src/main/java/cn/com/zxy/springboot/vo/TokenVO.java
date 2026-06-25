package cn.com.zxy.springboot.vo;

import lombok.Builder;
import lombok.Data;

/**
 * @author infosec
 * @since 2025/11/18
 */
@Builder
@Data
public class TokenVO {

    // private String status = "200";
    // private String msg = "成功";
    private String token;

}
