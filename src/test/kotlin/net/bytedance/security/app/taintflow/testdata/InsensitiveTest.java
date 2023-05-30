package net.bytedance.security.app.taintflow.testdata;

public class InsensitiveTest {
    public String source() {
        return "source";
    }

    public void sink(String s) {

    }

    public String checkString(String s) {
        if (s.isEmpty()) {
            throw new IllegalArgumentException("s is empty");
        }
        return s;
    }

    public void NormalFlow() {
        String s = checkString(source());
        sink(s);
    }

    public void HasInvalidFlow() {
        String s = checkString(source());
        String s2 = anotherString();
        sink(checkString(s2));
    }

    public String anotherString() {
        return "another";
    }
}
