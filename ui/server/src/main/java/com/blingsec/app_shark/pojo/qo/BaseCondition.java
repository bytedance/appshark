package com.blingsec.app_shark.pojo.qo;

import com.blingsec.app_shark.common.enums.TimeUnitEnum;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Data
public class BaseCondition implements Serializable {
    /** 第几页 **/
    private int page = 1;
    /** 每页多少条 **/
    private int rows = 20;
    /** 排序规则 **/
    private String orderBy;
    /** 时间单位 **/
    private TimeUnitEnum timeUnit;
    /** 年份 **/
    private String year;
    /** 选择的时间 **/
    private Integer seed;
    /** 开始时间 **/
    private Date startTime;
    /** 结束时间 **/
    private Date endTime;
}
