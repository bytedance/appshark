package com.blingsec.app_shark.common.base;

import com.blingsec.app_shark.common.enums.IsFlag;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;

@Getter
@Setter
public abstract class OrgIdEntity implements Serializable {
    /** 主键ID **/
    protected Integer id;
    /** 全局编码，用于之前的类似基线ID，测试用例ID等 **/
    protected String guid;
    /** 编号 **/
    protected String serialNumber;
    /** 是否公有 **/
    protected IsFlag shareFlag;
    /** UUID，添加唯一索引 **/
    protected String globalUniqueId;
    /** 创建时间 **/
    protected Date createdAt;
    /** 修改时间 **/
    protected Date updatedAt;
    /** 创建人id **/
    /** 是否已经被删除  0否 1是 **/
    protected IsFlag deletedFlag = IsFlag.NO;
}
