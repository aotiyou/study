package cn.com.zxy.springboot.controller;

import cn.com.zxy.springboot.dto.LicenceDTO;
import cn.com.zxy.springboot.dto.TaskDTO;
import cn.com.zxy.springboot.dto.TokenDTO;
import cn.com.zxy.springboot.vo.CommonResult;
import cn.com.zxy.springboot.vo.TokenVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * @author infosec
 * @since 2025/11/17
 */
@Slf4j
@RestController
public class NetCvmController {


    @GetMapping("/checkapi/gettoken")
    public CommonResult hello() {
        // return TokenVO.builder()
        //         .status("200").msg("成功").token(UUID.randomUUID().toString()).build();
        return CommonResult.success(UUID.randomUUID().toString());
    }


    @PostMapping("/checkapi/gettoken")
    public CommonResult getToken(@RequestBody TokenDTO dto) {
        log.info("Received getToken request: {}", dto);
        // return TokenVO.builder()
        //         .status("200").msg("成功").token(UUID.randomUUID().toString()).build();
        return CommonResult.success(UUID.randomUUID().toString());
    }

    @PostMapping("/checkapi/checktask/datareceive")
    public String dataReceive(@RequestBody TaskDTO dto) {
        log.info("Received dataReceive request: {}", dto);
        return "success";
    }

    @PostMapping("/outApi/token/getToken")
    public CommonResult<TokenVO> getToken_outApi(@RequestBody TokenDTO dto) {
        log.info("Received getToken request: {}", dto);
        return CommonResult.success(TokenVO.builder().token(UUID.randomUUID().toString()).build());
        // return CommonResult.failure();
    }

    @PostMapping("/outApi/push/pushLicenseInfo")
    public CommonResult<TokenVO> pushLicenseInfo_outApi(@RequestBody LicenceDTO dto) {
        log.info("Received licence request: {}", dto);
        return CommonResult.success();
    }

    @PostMapping("/outApi/push/pushKeyInfo")
    public CommonResult<TokenVO> pushKeyInfo_outApi(@RequestBody LicenceDTO dto) {
        log.info("Received key request: {}", dto);
        return CommonResult.success();
    }

}
