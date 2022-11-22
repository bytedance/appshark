package com.blingsec.app_shark.common.enums;

import com.blingsec.app_shark.common.base.BaseEnum;
import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public enum TimeUnitEnum implements BaseEnum {
    DAY(1, "今日"),
    WEEK(2, "周"),
    MONTH(3, "月"),
    QUARTER(4, "季"),
    HALF_YEAR(5, "半年"),
    YEAR(6, "年"),
    CUSTOM(7, "自定义");
    private final Integer code;
    private final String describe;

    TimeUnitEnum(Integer code, String describe) {
        this.code = code;
        this.describe = describe;
    }

}
