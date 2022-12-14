package com.blingsec.app_shark.pojo.entity;

import java.io.Serializable;
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
public class AppSharkTraversalSink implements Serializable {
    private Integer id;

    /**
    * 位置id
    */
    private Integer vulnerId;

    /**
    * 传播终点
    */
    private String sink;

    public AppSharkTraversalSink(Integer vulnerId, String sink) {
        this.vulnerId = vulnerId;
        this.sink = sink;
    }

    private static final long serialVersionUID = 1L;
}