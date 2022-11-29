package com.blingsec.app_shark.pojo.qo;

import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.List;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.pojo.qo
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月25日 10:09
 * -------------- -------------- ---------------------
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class DetailPageConditon extends BaseCondition implements Serializable {
    /** 任务id **/
    @NotNull(message = "任务ID不能为空")
    private Integer assessmentId;
    /**
     * 漏洞名称
     */
    private String vulnerName;
    /**
     * 漏洞等级
     */
    private String vulnerModel;
    /**
     * 行为多选（OR关系）
     */
    private List<String> vulnerNames;
    /**
     * 位置
     */
    private String position;
    /**
     * 堆栈
     */
    private String target;
}
