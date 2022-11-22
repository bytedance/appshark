package com.blingsec.app_shark.service;


import com.blingsec.app_shark.pojo.dto.Authorization;

/**
 * token相关业务逻辑
 */
public interface TokenService {
    /**
     * token生成，登录成功后调用
     * token生成结束后，放到redis或者缓存中，将时间设置为24小时
     *
     * @return 前缀+64位token
     */
    String generateToken();

    /**
     * 生成验证码所需令牌
     */
    String generateValidateToken();

    /**
     * token存redis
     */
    void putAuthorizationWithToken(String token, Authorization authorization);

    /**
     * 根据token获取账户信息
     *
     * @return 认证信息，可能为null
     */
    Authorization getAuthorizationByToken(String token);

    /**
     * 登录token生成
     */
    String generateToken(String username);

    /**
     * 将前缀等于用户名的这些权限全部失效
     */
    void invalidTokensByUsername(String username);

    /**
     * 获得用户的token(默认第一个)
     *
     * @param username
     * @return
     */
    String getTokenByUsername(String username);

    /**
     * 对比token串和用户名
     *
     * @param username
     * @param token
     * @return
     */
    boolean isSameUser(String username, String token);


}
