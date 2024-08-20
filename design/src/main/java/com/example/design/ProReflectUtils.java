package com.example.design;


import com.example.design.DefaultValue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author Hoary (hoary.huang@infosec.com.cn)
 * @org 北京信安世纪科技股份有限公司
 * @date 2024/7/29 15:31
 * @since NetSignServer5.7.2.2_build20240426
 */
public class ProReflectUtils {

    public static Properties load(String conf, Class clazz, Object obj) throws Exception {
        Properties pro;
        try{
            Field[] fields = clazz.getDeclaredFields();
            pro = loadProperties(conf);
            for (Field f: fields) {
                DefaultValue dv = f.getAnnotation(DefaultValue.class);
                if(dv == null){
                    continue;
                }
                f.setAccessible(true);
                String type = dv.type();
                if(CommonConstants.TI.equals(type)){
                    f.set(obj, loadPro(pro, dv.key(), dv.intValue()));
                }else if(CommonConstants.TB.equals(type)){
                    f.set(obj, loadPro(pro, dv.key(), dv.boolValue()));
                }else if(CommonConstants.TL.equals(type)){
                    f.set(obj, loadPro(pro, dv.key(), dv.longValue()));
                }else{
                    f.set(obj, loadPro(pro, dv.key(), dv.value()));
                }
            }
        }catch (Exception e){
            throw e;
        }
        return pro;
    }

    private static Object loadPro(Properties pro, String key, Object dfValue){
        String v = pro.getProperty(key);
        if(dfValue == null){
            return new String();
        }
        try {
            if(v != null){
                v = v.trim();
                if(dfValue instanceof String){
                    return v;
                }
                if(dfValue instanceof Integer){
                    return Integer.parseInt(v);
                }
                if(dfValue instanceof Boolean){
                    v = v.toLowerCase();
                    if(v.equals("yes")){
                        v = "true";
                    }else if(v.equals("no")){
                        v = "false";
                    }
                    return Boolean.parseBoolean(v);
                }
                if(dfValue instanceof Long){
                    return Long.parseLong(v);
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return dfValue;
    }

    public static Properties loadProperties(String file) throws IOException {
        InputStream in = null;
        try {
            File f = new File(file);
            if (f.exists()) {
                in = new FileInputStream(f);
            }else {
                in = ProReflectUtils.class.getClassLoader().getResourceAsStream(file);
            }
            Properties properties = new Properties();
            properties.load(in);
            return properties;
        } catch (IOException e) {
            throw e;
        } finally {
            FileUtils.closeQuiet(in);
        }
    }

    public static void createSampleConf(String path, Class clazz){
        Properties pro = null;
        try {
            pro = loadProperties(path);
        } catch (Exception e) {
        }
        Field[] fields = clazz.getDeclaredFields();
        try{
            if(pro == null){
                StringBuilder buf = new StringBuilder();
                for (Field f: fields) {
                    DefaultValue dv = f.getAnnotation(DefaultValue.class);
                    buf.append(dv.key()).append(" = ").append(dv.value()).append("\n");
                }
                FileUtils.saveFile(buf.toString().getBytes(), path + ".sample");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static StringBuilder saveObject2Pro(Class clazz, Object obj, Properties pro) throws Exception {
        String line = "\n";
        try{
            Field[] fields = clazz.getDeclaredFields();
            StringBuilder buf = new StringBuilder();
            for (Field f: fields) {
                DefaultValue dv = f.getAnnotation(DefaultValue.class);
                if(dv == null){
                    continue;
                }
                if(pro  != null && pro.getProperty(dv.key()) == null){
                    continue;
                }
                f.setAccessible(true);
                String title = dv.title();
                String comment = dv.comment();
                String cm = dv.disable();
                Object v = f.get(obj);
                if(DataUtils.isNotEmpty(title)){
                    buf.append(line).append(title).append(line);
                }
                if(DataUtils.isNotEmpty(comment)){
                    buf.append(comment).append(line);
                }
                String pre = "";
                if(DataUtils.isNotEmpty(cm) && DataUtils.isEmpty(v)){
                    pre = "#";
                }else{
                    cm = "";
                }
                buf.append(pre);
                buf.append(dv.key()).append(" = ").append(v == null ? "" : v).append(cm).append(line);
            }
            return buf;
        }catch (Exception e){
            throw e;
        }
    }

    public static void changeItemValue(String fieldName, String value, Class clazz, Object obj) throws Exception{
        try {
            Field f = clazz.getField(fieldName);
            f.setAccessible(true);
            DefaultValue dv = f.getAnnotation(DefaultValue.class);
            String type = dv.type();
            if(CommonConstants.TI.equals(type)){
                f.set(obj, Integer.parseInt(value));
            }else if(CommonConstants.TB.equals(type)){
                f.set(obj, Boolean.parseBoolean(value));
            }else if(CommonConstants.TL.equals(type)){
                f.set(obj, Long.parseLong(value));
            }else{
                f.set(obj, value);
            }
        }catch (Exception e){
            throw e;
        }
    }


    public static Map key2FieldName(Class clazz) throws Exception {
        try{
            Field[] fields = clazz.getDeclaredFields();
            Map<String, String> key2FieldNameMap = new HashMap(fields.length);
            for (Field f: fields) {
                DefaultValue dv = f.getAnnotation(DefaultValue.class);
                if(dv == null){
                    continue;
                }
                key2FieldNameMap.put(dv.key(), f.getName());
            }
            return key2FieldNameMap;
        }catch (Exception e){
            throw e;
        }
    }

}
