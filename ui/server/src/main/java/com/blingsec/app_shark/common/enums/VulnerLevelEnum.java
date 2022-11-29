package com.blingsec.app_shark.common.enums;

import com.blingsec.app_shark.common.base.BaseEnum;
import lombok.Getter;
import lombok.ToString;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.common.enums
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年11月03日 10:43
 * -------------- -------------- ---------------------
 */
@ToString
@Getter
public enum VulnerLevelEnum{
    SEVERITY("severity", "严重漏洞"),
    HIGH("high", "高危漏洞"),
    MIDDLE("middle", "中危漏洞"),
    LOW("low", "低危漏洞"),
    OTHER("other", "暂无级别");


    private final String name;
    private final String describe;

    VulnerLevelEnum(String name, String describe) {
        this.name = name;
        this.describe = describe;
    }

    public static String getValue(String name) {
        VulnerLevelEnum[] vulnerLevelEnums = values();
        for (VulnerLevelEnum vulnerLevelEnum : vulnerLevelEnums) {
            if ((vulnerLevelEnum.name).equals(name)) {
                return vulnerLevelEnum.describe;
            }
        }
        return null;
    }
}
