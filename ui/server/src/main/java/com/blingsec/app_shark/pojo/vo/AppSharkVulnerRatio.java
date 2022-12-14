package com.blingsec.app_shark.pojo.vo;

import lombok.Data;

import java.io.Serializable;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.vo
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月25日 10:33
 * -------------- -------------- ---------------------
 */
@Data
public class AppSharkVulnerRatio implements Serializable {
    //漏洞等级
    private String model;
    //漏洞总数
    private Integer countVulner;
    //漏洞比例
    private String vulnerRatio;
}
