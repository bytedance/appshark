package com.blingsec.app_shark.pojo.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.dto
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月18日 11:22
 * -------------- -------------- ---------------------
 */
@Data
public class ResultJson implements Serializable {
    @SerializedName("AppInfo")
    private AppInfo appInfo;

    @SerializedName("SecurityInfo")
    private SecurityInfo securityInfo;

    @SerializedName("UsePermissions")
    private List<String> usePermissions;

    @SerializedName("DefinePermissions")
    private Map<String,String> definePermissions;

    @SerializedName("BasicInfo")
    private BasicInfo basicInfo;

    @SerializedName("Profile")
    private String profile;
}
