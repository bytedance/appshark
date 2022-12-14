package com.blingsec.app_shark.pojo.entity;

import java.io.Serializable;
import java.util.Date;
import lombok.Data;
import lombok.NoArgsConstructor;

/**  
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.entity
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月19日 14:04
 * -------------- -------------- ---------------------
 */
/**
    * 使用权限表
    */
@Data
@NoArgsConstructor
public class AppSharkUsePermission implements Serializable {
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
    * 权限名称
    */
    private String name;

    /**
    * 权限释义
    */
    private String paraphrase;

    /**
    * 权限类型
    */
    private Integer type;
    /**
    * 任务id
    */
    private Integer assignmentId;

    private static final long serialVersionUID = 1L;

    public AppSharkUsePermission(String name, String paraphrase, Integer assignmentId) {
        this.name = name;
        this.paraphrase = paraphrase;
        this.assignmentId = assignmentId;
    }
}