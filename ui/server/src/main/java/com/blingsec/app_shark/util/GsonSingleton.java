package com.blingsec.app_shark.util;

import cn.hutool.core.util.NumberUtil;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author wenhailin
 * @date 2021/12/7-10:41
 */
@Slf4j
public class GsonSingleton {


    private static volatile Gson instance;

    private GsonSingleton() {
    }

    private static Date parseDate(String source) {
        /** 默认日期时间格式 **/
        String defaultDateTimeFormat = "yyyy-MM-dd HH:mm:ss";
        SimpleDateFormat simpleDateFormatter = new SimpleDateFormat(defaultDateTimeFormat);
        try {
            return simpleDateFormatter.parse(source);
        } catch (Exception e) {
            log.error("gson 转换时间类型出错", e);
            return null;
        }
    }

    public static Gson getInstance() {
        String defaultDateTimeFormat = "yyyy-MM-dd HH:mm:ss";
        if (instance == null) {
            synchronized (GsonSingleton.class) { // 注意这里是类级别的锁
                if (instance == null) {       // 这里的检测避免多线程并发时多次创建对象
                    instance = new GsonBuilder()
                            .registerTypeAdapter(Date.class, (JsonDeserializer<Date>) (json, typeOfT, context) -> {
                                String asString = json.getAsString();
                                if (StringUtils.isBlank(asString)) {
                                    return null;
                                }
                                return parseDate(asString);
                            })
                            .registerTypeAdapter(Integer.class, (JsonDeserializer<Integer>) (json, typeOfT, context) -> {
                                String asString = json.getAsString();
                                if (StringUtils.isBlank(asString)) {
                                    return null;
                                }
                                try {
                                    return NumberUtil.parseInt(asString);
                                } catch (Exception e) {
                                    log.error("gson 转换Integer类型出错", e);
                                    return null;
                                }
                            })
                            .registerTypeAdapter(Long.class, (JsonDeserializer<Long>) (json, typeOfT, context) -> {
                                String asString = json.getAsString();
                                if (StringUtils.isBlank(asString)) {
                                    return null;
                                }
                                try {
                                    return NumberUtil.parseLong(asString);
                                } catch (Exception e) {
                                    log.error("gson 转换Long类型出错", e);
                                    return null;
                                }
                            })
                            .setDateFormat(defaultDateTimeFormat)
                            .create();
                }
            }
        }
        return instance;
    }

}
