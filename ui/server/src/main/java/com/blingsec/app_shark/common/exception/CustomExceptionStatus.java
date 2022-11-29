package com.blingsec.app_shark.common.exception;

import java.io.Serializable;

public enum CustomExceptionStatus implements Serializable, IAPIResult {


    SUCCESS {
        public int getCode() {
            return 1;
        }

        public String getMessage() {
            return "成功";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    API_NOT_FIND {
        public int getCode() {
            return 2;
        }

        public String getMessage() {
            return "API不存在";
        }

        public Handler getHandler() {
            return Handler.SERVER;
        }
    },
    LIMIT_ERROR {
        public int getCode() {
            return 3;
        }

        public String getMessage() {
            return "调用频率超过限制";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    NO_AUTH {
        public int getCode() {
            return 4;
        }

        public String getMessage() {
            return "客户端的API权限不足";
        }

        public Handler getHandler() {
            return Handler.SERVER;
        }
    },
    NOT_LOGIN {
        public int getCode() {
            return 5;
        }

        public String getMessage() {
            return "未登录或者登录已超时";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    MAPI_ERROR {
        public int getCode() {
            return 6;
        }

        public String getMessage() {
            return "服务器内部错误";
        }

        public Handler getHandler() {
            return Handler.SERVER;
        }
    },
    BASE_ERROR {
        public int getCode() {
            return 7;
        }

        public String getMessage() {
            return "业务处理错误";
        }

        public Handler getHandler() {
            return Handler.USER;
        }
    },
    SECURITY_ERROR {
        public int getCode() {
            return 8;
        }

        public String getMessage() {
            return "客户端身份签名未通过";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    PARAM_ERROR {
        public int getCode() {
            return 9;
        }

        public String getMessage() {
            return "参数错误";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    INVOKER_INIT_FAIL {
        public int getCode() {
            return 10;
        }

        public String getMessage() {
            return "客户端身份初始化失败";
        }

        public Handler getHandler() {
            return Handler.SERVER;
        }
    },
    PROTOCOL_ERROR {
        public int getCode() {
            return 12;
        }

        public String getMessage() {
            return "请求协议不支持";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    SECRETKEY_EXPIRED {
        public int getCode() {
            return 13;
        }

        public String getMessage() {
            return "秘钥过期";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    TOKEN_INVALID {
        public String getMessage() {
            return "TOKEN失效";
        }

        public int getCode() {
            return 15;
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    SECURITY_KEY_IS_NULL {
        public int getCode() {
            return 17;
        }

        public String getMessage() {
            return "密钥为空";
        }

        public Handler getHandler() {
            return Handler.SERVER;
        }
    },
    ASYNC_TOKEN_MISSING {
        public int getCode() {
            return 18;
        }

        public String getMessage() {
            return "异步token缺失";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    FILTER_INTERRUPT {
        public int getCode() {
            return 19;
        }

        public String getMessage() {
            return "过滤器拒绝了该请求";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    INTERCEPTOR_INTERRUPT {
        public int getCode() {
            return 20;
        }

        public String getMessage() {
            return "拦截器拒绝了该请求";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    },
    API_UNABLE {
        public int getCode() {
            return 21;
        }

        public String getMessage() {
            return "该API已暂停使用";
        }

        public Handler getHandler() {
            return Handler.CLIENT;
        }
    };
    private CustomExceptionStatus() {
    }
}
