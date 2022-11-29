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
/**
    * 合规检测
    */
@Data
public class AppSharkCamilleInfo implements Serializable {
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
    * 规则类型
    */
    private String category;

    /**
    * 行为详情
    */
    private String detail;

    /**
    * 行为名称
    */
    private String name;

    private static final long serialVersionUID = 1L;
}