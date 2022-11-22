package com.blingsec.app_shark.service;


import com.blingsec.app_shark.common.enums.UidTypeEnum;

public interface UidService {
    /**
     * 获取并且新增UID
     *
     * @param type uid type
     * @param bits 填充位数，如为null，则默认为4位
     * @return uid
     */
    public String getAndIncrementUid(UidTypeEnum type, Integer bits);

    /**
     * 获取并且新增UID
     */
    public String getAndIncrementUid(UidTypeEnum type);
}
