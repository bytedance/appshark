package com.blingsec.app_shark.pojo.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.io.Serializable;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.dto
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月18日 14:29
 * -------------- -------------- ---------------------
 */
@Data
public class Vulner implements Serializable{
    @SerializedName("details")
    private Details details;
    @SerializedName("hash")
    private String hash;
    @SerializedName("possibility")
    private String possibility;
}
