package com.blingsec.app_shark.common.enums;

import com.blingsec.app_shark.common.base.BaseEnum;
import lombok.Getter;
import lombok.ToString;

/**
 * @author renxin
 */
@ToString
@Getter
public enum AssignmentProcessStatus implements BaseEnum {
    WAITING(0, "未开始"),
    PROCESSING(1, "进行中"),
    FINISHED(2, "检测成功"),
    ERROR(3, "检测失败");


    private final Integer code;
    private final String describe;

    AssignmentProcessStatus(Integer code, String describe) {
        this.code = code;
        this.describe = describe;
    }
}