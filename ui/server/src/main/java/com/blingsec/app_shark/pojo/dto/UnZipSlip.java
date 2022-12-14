package com.blingsec.app_shark.pojo.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.dto
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月18日 14:27
 * -------------- -------------- ---------------------
 */
@Data
public class UnZipSlip implements Serializable{
    @SerializedName("category")
    private String category;
    @SerializedName("detail")
    private String detail;
    @SerializedName("model")
    private String model;
    @SerializedName("name")
    private String name;
    @SerializedName("possibility")
    private String possibility;
    @SerializedName("vulners")
    private List<Vulner> vulners;
    @SerializedName("wiki")
    private String wiki;
    @SerializedName("deobfApk")
    private String deobfApk;
}
