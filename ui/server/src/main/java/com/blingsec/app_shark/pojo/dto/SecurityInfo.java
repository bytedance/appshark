package com.blingsec.app_shark.pojo.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.io.Serializable;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.dto
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月18日 11:28
 * -------------- -------------- ---------------------
 */
@Data
public class SecurityInfo implements Serializable {
    @SerializedName("FileRisk")
    private FileRisk fileRisk;
}
