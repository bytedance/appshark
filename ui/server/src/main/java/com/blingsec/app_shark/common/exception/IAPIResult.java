package com.blingsec.app_shark.common.exception;

public interface IAPIResult {
    int getCode();

    String getMessage();

    Handler getHandler();

    enum Handler {
        SERVER,
        CLIENT,
        USER;

        private Handler() {
        }
    }
}
