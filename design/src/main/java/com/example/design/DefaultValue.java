package com.example.design;

import java.lang.annotation.*;

/**
 * @author Hoary (hoary.huang@infosec.com.cn)
 * @org 北京信安世纪科技股份有限公司
 * @date 2020/3/2 15:53
 * @since 5.5.40.12 Patch32.1 +
 */
@Inherited
@Documented
@Target({ElementType.FIELD, ElementType.LOCAL_VARIABLE, ElementType.PARAMETER, ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface DefaultValue {

    String value() default "";

    boolean boolValue() default false;

    int intValue() default 0;

    long longValue() default 0;

    String type() default "";

    String key();

    String comment() default "";

    String title() default "";

    String disable() default "";
}
