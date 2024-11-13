package cn.com.zxy.springboot.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * @author infosec
 * @since 2024/11/13
 */
@Slf4j
@RestController
public class ImageController {

    @GetMapping("/image")
    public ResponseEntity<InputStreamResource> downloadImage() {
        String localFilePath = "D:/opt/infosec/CCypher/openapi/VSM-All-container-C249B20016000n0-1731495312229-93d354c0-371e-4ff1-aa72-ef73802d9e50.tar.gz";
        File localFile = new File(localFilePath);

        if (!localFile.exists()) {
            return ResponseEntity.notFound().build();
        }

        try {
            FileInputStream fileInputStream = new FileInputStream(localFile);
            InputStreamResource resource = new InputStreamResource(fileInputStream);

            // 设置响应头
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + localFile.getName());
            headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE);
            headers.add(HttpHeaders.CONTENT_LENGTH, String.valueOf(localFile.length()));

            // 返回文件作为响应体
            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(localFile.length())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }


}
