package cn.com.zxy.springboot.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * @author infosec
 * @since 2024/11/13
 */
@Slf4j
@RestController
public class UpgradeController {

    @GetMapping("upgrade/upload/{upgradeFileName}")
    public void uploadUpgradeFile(@PathVariable String upgradeFileName, HttpServletResponse response) {
        String filePath = "D:/opt/infosec/CCypher/openapi/" + upgradeFileName;
        File file = new File(filePath);
        if (!file.exists()) {
            log.error("method=downCng||msg=cnf exe not exist||filePath={}", filePath);
            throw new RuntimeException("升级文件不存在");
        }
        String filename = URLEncoder.encode(file.getName(), StandardCharsets.UTF_8);

        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        response.setHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION);
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment;fileName=" + filename);


        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(filePath));
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;

            // 读取文件并写入到响应输出流中
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        } catch (Exception e) {
            throw new RuntimeException("升级文件上传失败");
        }
    }


}
