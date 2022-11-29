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
@Data
public class AppSharkTraversalVulner implements Serializable {
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
    * 漏洞id
    */
    private Integer traversalInfoId;

    /**
    * 位置
    */
    private String position;

    /**
    * 详情
    */
    private String url;

    /**
    * 分析入口
    */
    private String entryMethod;

    private static final long serialVersionUID = 1L;
}