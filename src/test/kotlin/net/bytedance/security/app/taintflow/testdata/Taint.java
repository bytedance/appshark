package net.bytedance.security.app.taintflow.testdata;

public class Taint {
    public static Object source() {
        return new Object();
    }

    public static void sink(Object object) {
    }
    public static void notSink(Object object) {
    }
    public static Object sanitize(Object object) {
        return object;
    }
}
