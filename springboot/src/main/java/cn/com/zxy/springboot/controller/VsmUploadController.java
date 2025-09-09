package cn.com.zxy.springboot.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

/**
 * @author infosec
 * @since 2024/11/13
 */
@Slf4j
@RestController
public class VsmUploadController {

    @PostMapping("upload")
    public ResponseEntity upload(@RequestPart("file") MultipartFile file, @RequestParam("requestId") String requestId,
                                 @RequestParam("info") String info) {
        log.info("requestId:{},info:{}", requestId, info);

        // 定义文件保存路径
        String localFilePath = "D:/opt/infosec/CCypher/openapi/" + file.getOriginalFilename();

        // 保存文件到本地
        try {
            File localFile = new File(localFilePath);
            file.transferTo(localFile);  // 将上传的 MultipartFile 文件保存到指定位置
            log.info("File saved successfully at {}", localFilePath);
        } catch (IOException e) {
            log.error("Failed to save file locally", e);
            return ResponseEntity.ok("Error saving file");
        }

        return ResponseEntity.status(200).body("Success");

    }

}
