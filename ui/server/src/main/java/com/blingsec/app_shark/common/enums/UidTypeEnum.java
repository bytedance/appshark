package com.blingsec.app_shark.common.enums;

import lombok.Getter;
import lombok.ToString;

/**
 * UID相关
 */
@Getter
@ToString
public enum UidTypeEnum {
    /**
     * 任务
     */
    RWID(0, "任务", "proj_task_assignment");

    private final Integer code;
    private final String describe;
    private String tableName;
    private String primaryKeyName = "guid";

    UidTypeEnum(Integer code, String describe) {
        this.code = code;
        this.describe = describe;
    }

    UidTypeEnum(Integer code, String describe, String tableName) {
        this.code = code;
        this.describe = describe;
        this.tableName = tableName;
    }

    UidTypeEnum(Integer code, String describe, String tableName, String primaryKeyName) {
        this.code = code;
        this.describe = describe;
        this.tableName = tableName;
        this.primaryKeyName = primaryKeyName;
    }

    public Integer getCode() {
        return code;
    }

    public String getDescribe() {
        return describe;
    }
}