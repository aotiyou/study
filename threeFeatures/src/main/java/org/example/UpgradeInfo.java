package org.example;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

/**
 * @author infosec
 * @since 2024/7/12
 */
@Data
public class UpgradeInfo extends BaseInfo {

    @ApiModelProperty(value = "升级包版本")
    private String packVersion;

    @ApiModelProperty(value = "升级包地址")
    private String packUrl;

    @ApiModelProperty(value = "签名算法")
    private String alg;

    @ApiModelProperty(value = "数字签名值", example = "")
    private String sign;

}
