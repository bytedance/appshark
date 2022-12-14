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
 * @Creation Date : 2022年10月18日 14:30
 * -------------- -------------- ---------------------
 */
@Data
public class Details implements Serializable {
    @SerializedName("position")
    private String position;
    @SerializedName("Sink")
    private String sink;
    @SerializedName("entryMethod")
    private String entryMethod;
    @SerializedName("Source")
    private String source;
    @SerializedName("url")
    private String url;
    @SerializedName("target")
    private List<String> target;
}
