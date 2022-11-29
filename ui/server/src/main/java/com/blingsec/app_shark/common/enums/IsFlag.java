package com.blingsec.app_shark.common.enums;

import com.blingsec.app_shark.common.base.BaseEnum;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public enum IsFlag implements BaseEnum {
    NO(0, "否"), YES(1, "是");
    private final Integer code;
    private final String describe;

    IsFlag(Integer code, String describe) {
        this.code = code;
        this.describe = describe;
    }
}
