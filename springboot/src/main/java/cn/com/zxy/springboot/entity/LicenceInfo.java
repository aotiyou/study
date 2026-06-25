package cn.com.zxy.springboot.entity;

import lombok.Data;

/**
 *
 * @auther: infosec
 * @date: 2026/6/25
 * @description: cn.com.zxy.springboot.entity
 * @version: 1.0
 */
@Data
public class LicenceInfo {

    /**
     * 到期时间
     */
    private String expirationTime;

    /**
     * 备注
     */
    private String remark;

}
