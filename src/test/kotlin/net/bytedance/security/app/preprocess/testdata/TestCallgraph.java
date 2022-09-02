package net.bytedance.security.app.preprocess.testdata;

public class TestCallgraph {
    void calldirect(Sub s) {
        df1(s);
        sinkDirect();
    }

    void df1(Sub s) {
        df2(s);
    }

    void df2(Sub s) {
        df3(s);
    }

    void df3(Sub s) {
        s.methodImplementedInSub();
    }

    void sinkDirect() {
        sink();
    }

    void sink() {

    }

    void callHeir(Base b) {
        hf1(b);
        sinkDirect();
    }

    void hf1(Base s) {
        hf2(s);
    }

    void hf2(Base s) {
        hf3(s);
    }

    void hf3(Base s) {
        s.methodImplementedInSub2();
    }
}
