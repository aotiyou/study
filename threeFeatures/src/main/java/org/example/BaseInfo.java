package org.example;

import io.swagger.annotations.ApiModelProperty;

/**
 * @author infosec
 * @since 2024/7/12
 */
public abstract class BaseInfo {

    @ApiModelProperty(value = "请求流水号")
    private String requestId;

    @ApiModelProperty(value = "操作类型")
    private String oprType;

    @ApiModelProperty(value = "回调地址")
    private String callbackUrl;

    abstract  String getPackVersion();

    abstract String getPackUrl();

    abstract String getAlg();

    abstract String getSign();

}
