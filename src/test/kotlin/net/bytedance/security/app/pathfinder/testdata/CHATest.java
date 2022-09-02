package net.bytedance.security.app.pathfinder.testdata;

public class CHATest {
    static public class Base {
        public Object getSource() {
            return "";
        }
    }

    static public class Sub extends Base {
        @Override
        public Object getSource() {
            return Taint.source();
        }
    }

    static public class ClassFlow {
        void callsink(Object arg) {
            Taint.sink(arg);
        }

        Object f(Base b) {
            return b.getSource();
        }

        void flow() {
            Base b = new Base();
            Object obj = f(b);
            callsink(obj);
        }
    }

}
