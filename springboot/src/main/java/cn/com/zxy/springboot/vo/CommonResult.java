package cn.com.zxy.springboot.vo;

import lombok.Builder;
import lombok.Data;

/**
 *
 * @auther: infosec
 * @date: 2026/6/24
 * @description: cn.com.zxy.springboot.vo
 * @version: 1.0
 */
@Data
public class CommonResult<T> {

    private String status;
    private String msg;

    private T data;

    public CommonResult(String status, String msg, T data) {
        this.status = status;
        this.msg = msg;
        this.data = data;
    }

    public static CommonResult success() {
        return new CommonResult("200", "操作成功", null);
    }

    public static CommonResult success(Object data) {
        return new CommonResult("200", "操作成功", data);
    }

    public static CommonResult failure() {
        return new CommonResult("500", "操作失败", null);
    }
}
