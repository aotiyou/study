package org.example;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

/**
 * @author infosec
 * @since 2024/7/12
 */
@Data
public class BackupInfo extends BaseInfo {

    @ApiModelProperty(value = "备份数据包地址")
    private String backupUrl;

    @ApiModelProperty(value = "签名算法")
    private String alg;

    @ApiModelProperty(value = "数字签名值", example = "")
    private String sign;

}
