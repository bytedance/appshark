package com.blingsec.app_shark.service.impl;

import cn.hutool.core.collection.CollectionUtil;
import com.blingsec.app_shark.common.Constants;
import com.blingsec.app_shark.pojo.dto.Authorization;
import com.blingsec.app_shark.service.RedisService;
import com.blingsec.app_shark.service.TokenService;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Random;
import java.util.Set;

import static com.blingsec.app_shark.common.Constants.Token.TOKEN_EXPIRE_TIME;


@Slf4j
@Service
public class TokenServiceImpl implements TokenService {
    @Autowired
    private Gson gson;
    @Autowired
    private RedisService redisService;
    @Autowired
    private Environment environment;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    private final Random random = new Random();

    private static final char[] hats = new char[]{
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };

    public TokenServiceImpl() throws NoSuchAlgorithmException {
    }

    @Override
    public String generateToken() {
        log.info("开始生成token...");
        // Token的前缀
        String token = this.pullingOfHats();
        token = Constants.Auth.TOKEN_PREFIX + token;
        log.info("Token生成结束，token字符为{}", token);
        return token;
    }

    private String pullingOfHats() {
        log.trace("pullingOfHats  starting .....................................................");
        int tokenLength = Integer.parseInt(environment.getProperty("token.length", "64"));
        log.trace("pullingOfHats  ending   {}. .....................................................", tokenLength);
        StringBuilder builder = new StringBuilder();
        log.trace("hats length is {}", hats.length);
        for (int i = 0; i < tokenLength; i++) {
            int index = random.nextInt(hats.length);
            builder.append(hats[index]);
        }
        log.trace("生成的token验证码为：{}   ...................................................", builder);
        return builder.toString();
    }

    @Override
    public String generateValidateToken() {
        return this.pullingOfHats();
    }


    /**
     * token存redis
     */
    @Override
    public void putAuthorizationWithToken(String token, Authorization authorization) {
        redisService.set(token, gson.toJson(authorization), TOKEN_EXPIRE_TIME);
    }

    /**
     * 根据token获取账户信息
     *
     * @return 认证信息，可能为null
     */
    @Override
    public Authorization getAuthorizationByToken(String token) {
        Object obj = redisService.get(token);
        if (Objects.isNull(obj)) {
            return null;
        }
        return gson.fromJson(obj.toString(), Authorization.class);
    }

    @Override
    public String generateToken(String username) {
        log.info("开始生成token...");
        // Token的前缀
        String token = this.pullingOfHats();
        token = this.getLoginPrefix(username) + token;
        log.info("Token生成结束，token字符为{}", token);
        return token;
    }

    private String getLoginPrefix(String username) {
        return Constants.Auth.TOKEN_PREFIX + username + "_";
    }

    @Override
    public boolean isSameUser(String username, String token) {
        if (StringUtils.isBlank(username) || StringUtils.isBlank(token)) {
            return false;
        }
        return token.contains(Constants.Auth.TOKEN_PREFIX + username + "_");
    }

    @Override
    public void invalidTokensByUsername(String username) {
        log.info("开始使该用户其他登录的信息失效，用户username为：{}", username);
        Set<String> keys = redisTemplate.keys(this.getLoginPrefix(username) + "*");
        //invalid
        if (CollectionUtil.isNotEmpty(keys)) {
            log.info("当前登录的其他用户的大小为：{}", keys.size());
            redisTemplate.delete(keys);
        }
    }

    @Override
    public String getTokenByUsername(String username) {
        log.info("验证用户是否是登录状态，{}", username);
        Set<String> keys = redisTemplate.keys(this.getLoginPrefix(username) + "*");
        if (CollectionUtil.isEmpty(keys)) {
            return null;
        }
        return keys.iterator().next();
    }

}
