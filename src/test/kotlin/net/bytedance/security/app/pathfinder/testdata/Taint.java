package net.bytedance.security.app.pathfinder.testdata;

public class Taint {
    public static Object source() {
        return new Object();
    }

    public static void sink(Object object) {
    }

    public static Object sanitize(Object object) {
        return object;
    }
}
