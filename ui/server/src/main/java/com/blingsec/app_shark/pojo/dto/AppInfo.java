package com.blingsec.app_shark.pojo.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.io.Serializable;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.dto
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月18日 11:24
 * -------------- -------------- ---------------------
 */
@Data
public class AppInfo implements Serializable{
    /** app名称 **/
    @SerializedName("AppName")
    private String appName;

    /** 包名称 **/
    @SerializedName("PackageName")
    private String packageName;

    /** min_sdk **/
    @SerializedName("min_sdk")
    private Integer minSdk;

    /** target_sdk **/
    @SerializedName("target_sdk")
    private Integer targetSdk;

    /** versionCode **/
    @SerializedName("versionCode")
    private Integer versionCode;

    /** 版本号 **/
    @SerializedName("versionName")
    private String versionName;
}
