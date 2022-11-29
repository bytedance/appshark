package com.blingsec.app_shark.pojo.entity;

import java.io.Serializable;
import java.util.Date;
import lombok.Data;

/**  
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.entity
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月19日 14:04
 * -------------- -------------- ---------------------
 */
/**
    * App详情表
    */
@Data
public class AppSharkAppInfo implements Serializable {
    private Integer id;

    /**
    * 创建时间
    */
    private Date createdAt;

    /**
    * 修改时间
    */
    private Date updatedAt;

    /**
    * 任务id
    */
    private Integer assignmentId;

    /**
    * App名称
    */
    private String appName;

    /**
    * 包名
    */
    private String packageName;

    /**
    * min_sdk
    */
    private Integer minSdk;

    /**
    * target_sdk
    */
    private Integer targetSdk;

    /**
    * 版本
    */
    private String versionName;

    private static final long serialVersionUID = 1L;
}