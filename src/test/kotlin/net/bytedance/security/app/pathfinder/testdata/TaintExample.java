package net.bytedance.security.app.pathfinder.testdata;

public class TaintExample {
    static void TaintCrossStaticMethod() {
        Taint.sink(staticSource2());
    }

    static Object staticSource1() {
        return Taint.source();
    }

    static Object staticSource2() {
        return staticSource1();
    }

    void TaintCrossInstanceMethod() {
        Taint.sink(instanceSource2());
    }

    Object instanceSource1() {
        return Taint.source();
    }

    Object instanceSource2() {
        return instanceSource1();
    }
}
