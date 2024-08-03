package net.bytedance.security.app.sanitizer.v2.testdata;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class TestSdCardVisit {
    public static String getExternalFilesDir() {
        return "";
    }

    public static String getSoName() {
        return "test.so";
    }

    public static String getNonSoName() {
        return "test.txt";
    }

    public static void TestProblem1() throws IOException {
        String content = "";
        String fileName = getExternalFilesDir() + "/" + getSoName();
        File file = new File(fileName);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(3);
    }

    public static void TestNoProblem1() throws IOException {
        String content = "";
        String fileName = getExternalFilesDir() + "/" + getNonSoName();
        File file = new File(fileName);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(3);
    }

    public static void TestNoProblem2() throws IOException {
        String content = "";
        String fileName = "/tmp" + "/" + ".so";
        File file = new File(fileName);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(3);
    }

    public static void f() throws IOException {
        TestProblem1();
        TestNoProblem1();
        TestNoProblem2();
    }
}
