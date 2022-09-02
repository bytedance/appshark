package net.bytedance.security.app.preprocess.testdata;

public class Sub2 extends Base {
    public Object field1 = null;

    Sub2() {
        field1 = "field_const_str";
    }

    public Object methodImplementedInSub2() {
        return new Object();
    }

    public Object anotherf() {
        return this.field1;
    }

    public Object allImplemented() {
        return anotherf();
    }
}