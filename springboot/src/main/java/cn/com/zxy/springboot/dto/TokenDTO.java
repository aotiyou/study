package cn.com.zxy.springboot.dto;

import lombok.Data;

/**
 * @author infosec
 * @since 2025/11/18
 */
@Data
public class TokenDTO {

    /**
     * 一键巡检组件对接CVM用户名(提供CVM系统使用)
     */
    private String name;

    /**
     * 一键巡检组件对接CVM口令(提供CVM系统使用)
     */
    private String password;

    private String nonce;
}
