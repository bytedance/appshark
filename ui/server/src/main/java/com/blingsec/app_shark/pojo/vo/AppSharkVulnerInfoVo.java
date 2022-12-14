package com.blingsec.app_shark.pojo.vo;

import com.blingsec.app_shark.pojo.entity.AppSharkTraversalSink;
import com.blingsec.app_shark.pojo.entity.AppSharkTraversalSource;
import com.blingsec.app_shark.pojo.entity.AppSharkTraversalTarget;
import com.blingsec.app_shark.pojo.entity.AppSharkTraversalVulner;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.vo
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月25日 10:37
 * -------------- -------------- ---------------------
 */
@Data
public class AppSharkVulnerInfoVo implements Serializable {
    private Integer id;
    /**
     * 任务id
     */
    private Integer assignmentId;

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
     * 漏洞等级
     */
    private String model;
    /**
     * 漏洞详情
     */
    private AppSharkTraversalVulner appSharkTraversalVulner;
    /**
     * 传播起点
     */
    private List<AppSharkTraversalSource> appSharkTraversalSources;
    /**
     * 传播终点
     */
    private List<AppSharkTraversalSink> appSharkTraversalSinks;
    /**
     * 传播途径
     */
    private List<AppSharkTraversalTarget> appSharkTraversalTargets;
}
