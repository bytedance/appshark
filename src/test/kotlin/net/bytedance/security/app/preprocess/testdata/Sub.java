package net.bytedance.security.app.preprocess.testdata;


public class Sub extends Base {
    public static String s = "static_field_const_str";
    public String SubField1 = "SubField1";
    public Object field1 = null;

    public Object methodImplementedInSub() {
        String s1 = s;
        s1 += s;
        s1 += SubField1;
        return s1;
    }

    public Object callMethodImplementedInParent() {
        Object o1 = this.methodImplementedInSub2();
        Object o2 = this.methodImplementedInSub2();
        return o1.toString() + o2.toString();
    }

    public Object callInterface(Interface i) {
        return i.methodImplementedInSub();
    }

    public Object callInterfaceNoImplementation(InterfaceNonExist i) {
        return i.noImplementationMethod();
    }

    public static void newInstance() {
        Interface b = new Sub();
        Interface b1 = new Base();
        Interface b2 = new Sub2();
        Base b3 = new Sub();
        Base b4 = new Sub2();
    }

    public void callConstString() {
        System.out.println("conststring");
    }

    public Object allImplemented() {
        return super.allImplemented();
    }
}