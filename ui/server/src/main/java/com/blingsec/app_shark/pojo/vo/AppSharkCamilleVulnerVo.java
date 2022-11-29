package com.blingsec.app_shark.pojo.vo;

import com.blingsec.app_shark.pojo.entity.AppSharkCamilleVulner;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;
import java.util.List;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.vo
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月26日 15:08
 * -------------- -------------- ---------------------
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class AppSharkCamilleVulnerVo extends AppSharkCamilleVulner implements Serializable {
    /**
     * 漏洞类型
     */
    private String category;

    /**
     * 漏洞描述
     */
    private String detail;

    /**
     * 漏洞名称
     */
    private String name;
    /**
     * 堆栈列表
     */
    private List<String> targets;
}
