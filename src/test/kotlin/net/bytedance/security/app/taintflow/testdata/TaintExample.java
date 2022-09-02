package net.bytedance.security.app.taintflow.testdata;

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
    Object through(Object arg){
        return arg;
    }
    void flowCrossMethod(){
        Object source=Taint.source();
        Object o1=through(source);
        Taint.notSink(o1);
        Object s2=new Object();
        Object o2=through(s2);
        Taint.sink(o2);
    }
}
