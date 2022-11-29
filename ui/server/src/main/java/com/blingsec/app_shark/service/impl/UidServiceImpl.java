package com.blingsec.app_shark.service.impl;

import cn.hutool.core.util.StrUtil;
import com.blingsec.app_shark.common.enums.UidTypeEnum;
import com.blingsec.app_shark.service.RedisService;
import com.blingsec.app_shark.service.UidService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Service
public class UidServiceImpl implements UidService {
    /** UID默认位数 **/
    private static final int FILLED_UID_LENGTH = 4;

    @Autowired
    private RedisService redisService;

    @RequestMapping("generate")
    public String getAndIncrementUid(UidTypeEnum type, Integer bits) {

        Long id = redisService.getAndIncrement(type.name());
        //在下面刷新到数据库前，需要保证redis领先于数据库
        String uid = this.populateUid(type, id, bits);
        if (log.isTraceEnabled()) {
            log.trace("自增ID，ID类型为{}，自增后的ID结果为{}", type, uid);
        }
        return uid;
    }

    @Override
    public String getAndIncrementUid(UidTypeEnum type) {
        return this.getAndIncrementUid(type, 4);
    }

    /**
     * 填充UID
     */
    private String populateUid(UidTypeEnum type, Long id, Integer bits) {
        if (bits == null) {
            return type.name() + StrUtil.fill(id.toString(), '0', FILLED_UID_LENGTH, true);
        }
        return type.name() + StrUtil.fill(id.toString(), '0', bits, true);
    }
}
