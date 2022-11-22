package com.blingsec.app_shark.service.impl;

import com.blingsec.app_shark.common.Constants;
import com.blingsec.app_shark.service.RedisService;
import com.blingsec.app_shark.service.TokenValidService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * @author wenhailin
 */
@Slf4j
@Service
public class TokenValidServiceImpl implements TokenValidService {

    @Autowired
    private RedisService redisService;

    /**
     * 令牌有效性刷新
     */
    public void refresh(String token) {
        if (log.isTraceEnabled()) {
            log.trace("开始刷新token有效期，token为：{}", token);
        }
        // token刷新
        redisService.expire(token, Constants.Token.TOKEN_EXPIRE_TIME);
        if (log.isTraceEnabled()) {
            log.trace("Token有效期刷新结束，token为：{}", token);

        }
    }

    /**
     * 验证token
     */
    public Boolean validate(String token) {
        if (log.isTraceEnabled()) {
            log.trace("开始验证token的有效性，token为：{}", token);
        }
        Object obj = redisService.get(token);
        if (Objects.isNull(obj)) {
            log.warn("Token不存在，token信息为：{}", token);
            return false;
        }
        if (log.isTraceEnabled()) {
            log.trace("Token有效期验证结束，验证结果为：{}", true);
        }
        return true;
    }

    /**
     * 验证token，并且刷新有效性
     */
    public Boolean validateAndRefresh(String token) {
        Boolean result = this.validate(token);
        if (result) {
            this.refresh(token);
            return true;
        }
        return false;
    }
}
