package net.bytedance.security.app.preprocess.testdata;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Apple {

    private int price;

    public int getPrice() {
        return price;
    }

    public void setPrice(int price) {
        this.price = price;
    }

    public void normalCall() {
        Apple apple = new Apple();
        apple.setPrice(5);
        System.out.println("Apple Price:" + apple.getPrice());
    }

    public void reflectionCall() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Class clz = Class.forName("net.bytedance.security.app.preprocess.testdata.Apple");
        Method setPriceMethod = clz.getMethod("setPrice", int.class);
        Constructor appleConstructor = clz.getConstructor();
        Object appleObj = appleConstructor.newInstance();
        setPriceMethod.invoke(appleObj, 14);
        Method getPriceMethod = clz.getMethod("getPrice");
        System.out.println("Apple Price:" + getPriceMethod.invoke(appleObj));
    }

    public void reflectionCall2() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Class clz = Class.forName("net.bytedance.security.app.preprocess.testdata.Apple");
        Method setPriceMethod = clz.getMethod("setPrice", int.class);
        Constructor appleConstructor = clz.getConstructor();
        Object appleObj = appleConstructor.newInstance();
        setPriceMethod.invoke(appleObj, 14);
        Method getPriceMethod = clz.getMethod("getPrice");
        System.out.println("Apple Price:" + getPriceMethod.invoke(appleObj));

        Class clz2 = Class.forName("net.bytedance.security.app.preprocess.testdata.Apple");
        Method setPriceMethod2 = clz2.getMethod("setPrice", int.class);
        Constructor appleConstructor2 = clz2.getConstructor();
        Object appleObj2 = appleConstructor2.newInstance();
        setPriceMethod2.invoke(appleObj, 14);
        Method getPriceMethod2 = clz2.getMethod("getPrice");
        System.out.println("Apple Price:" + getPriceMethod2.invoke(appleObj));
    }
}
