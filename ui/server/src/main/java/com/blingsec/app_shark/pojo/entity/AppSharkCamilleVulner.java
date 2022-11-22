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
public class AppSharkCamilleVulner implements Serializable {
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
    * 合规检测行为id
    */
    private Integer camilleInfoId;

    /**
    * 链接
    */
    private String url;

    /**
    * 位置
    */
    private String position;

    private static final long serialVersionUID = 1L;
}