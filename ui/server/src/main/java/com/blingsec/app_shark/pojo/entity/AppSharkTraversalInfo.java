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
public class AppSharkTraversalInfo implements Serializable {
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

    private static final long serialVersionUID = 1L;
}