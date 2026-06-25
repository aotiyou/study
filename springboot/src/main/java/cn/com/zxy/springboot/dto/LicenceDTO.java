package cn.com.zxy.springboot.dto;

import cn.com.zxy.springboot.entity.LicenceInfo;
import lombok.Data;

import java.util.List;

/**
 *
 * @auther: infosec
 * @date: 2026/6/24
 * @description: cn.com.zxy.springboot.dto
 * @version: 1.0
 */
@Data
public class LicenceDTO {

    private List<LicenceInfo> data;

}
