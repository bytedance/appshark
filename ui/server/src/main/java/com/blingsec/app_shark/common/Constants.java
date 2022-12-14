package com.blingsec.app_shark.common;

public class Constants {

    /**
     * 实用程序类是static成员的集合，并不打算实例化。甚至可以扩展的抽象实用程序类也不应具有公共构造函数。
     * Java向每个未显式定义至少一个类的类添加一个隐式公共构造函数。因此，至少应定义一个非公共构造函数。
     */
    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static class Token {
        /**
         * 默认过期时间 默认60秒
         **/
        public static final Integer IMAGE_CODE_TIMEOUT = 120;
        /**
         * Token过期时间2小时
         */
        public static final long TOKEN_EXPIRE_TIME = 2 * 60 * 60L;
        /**
         * 密码错误计时15分钟
         */
        public static final long LOGIN_FAIL_EXPIRE_TIME = 15 * 60L;
    }

    public static class Auth {
        private Auth() {
            throw new IllegalStateException("Utility class");
        }

        /**
         * Authorization 请求头
         */
        public static final String HEADER = "Authorization";
        /**
         * Authorization TOKEN的前缀
         */
        public static final String TOKEN_PREFIX = "auth_token_";
    }
}
