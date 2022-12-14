package com.blingsec.app_shark.pojo.entity;

import java.io.Serializable;

import lombok.AllArgsConstructor;
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
@Data
@NoArgsConstructor
public class AppSharkCamilleTarget implements Serializable {
    private Integer id;

    /**
    * 位置id
    */
    private Integer vulnerId;

    /**
    * 堆栈
    */
    private String target;

    public AppSharkCamilleTarget(Integer vulnerId, String target) {
        this.vulnerId = vulnerId;
        this.target = target;
    }

    private static final long serialVersionUID = 1L;
}