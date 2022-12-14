package com.blingsec.app_shark.util;


import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

/**
 * 硬盘工具类
 *
 * @author jing
 * @date 2021-08-03
 */
@Slf4j
public class DiskUtil {

    public static Map<String, Object> getDiskInfo(String path) {
        //判断是否为linux 系统
        if (isLinux()) {
            //是linux系统
            return getLinuxDiskInfo(path);
        } else if (isWindow()) {
            //是window
            return getWindowDiskInfo(path);
        }
        return null;
    }

    private static void getDiskInfoByPath() {
        File[] disks = File.listRoots();
        for (File file : disks) {
            System.out.print(file.getPath() + "    ");
            // 空闲空间
            log.info("空闲未使用 = " + file.getFreeSpace() / 1024 / 1024 + "M" + "    ");
            // 已用空间
            log.info("已经使用 = " + file.getUsableSpace() / 1024 / 1024 + "M" + "    ");
            // 总空间
            log.info("总容量 = " + file.getTotalSpace() / 1024 / 1024 + "M" + "    ");
            log.info("------------------------");
        }
    }

    private static Map<String, Object> getWindowDiskInfo(String path) {
        File file = new File(path);
        Map<String, Object> map = new HashMap<String, Object>(3);
        // 空闲空间
        map.put("free", file.getFreeSpace());
        log.info("空闲空间：" + file.getFreeSpace());
        // 已用空间
        map.put("used", (file.getTotalSpace() - file.getFreeSpace()));
        log.info("已使用空间大小：" + (file.getTotalSpace() - file.getFreeSpace()));
        // 总空间
        map.put("total", file.getTotalSpace());
        log.info("总空间大小：" + file.getTotalSpace());
        return map;
    }

    /**
     * G--查看硬盘空间大小
     */
    private static Map<String, Object> getLinuxDiskInfoG(String path) {
        Map<String, Object> map = new HashMap<>(5);
        try {
            Runtime rt = Runtime.getRuntime();
            // df -hl 查看硬盘空间
            Process p = rt.exec("df -hl " + path);
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(
                        p.getInputStream()));
                String str = null;
                String[] strArray = null;
                int line = 0;
                while ((str = in.readLine()) != null) {
                    line++;
                    if (line != 2) {
                        continue;
                    }
                    int m = 0;
                    strArray = str.split(" ");
                    for (String para : strArray) {
                        if (para.trim().length() == 0) {
                            continue;
                        }
                        ++m;
                        if (para.endsWith("G") || para.endsWith("Gi")) {
                            Long spaceSize = getSpaceSize(para);
                            // 目前的服务器
                            if (m == 2) {
                                map.put("total", spaceSize);
                                log.info("总空间大小：" + para + "G------>" + spaceSize + "b");
                            }
                            if (m == 3) {
                                map.put("used", spaceSize);
                                log.info("已使用空间大小：" + para + "G------>" + spaceSize + "b");
                            }
                            if (m == 4) {
                                map.put("free", spaceSize);
                                log.info("可用空间大小：" + para + "G------>" + spaceSize + "b");
                            }

                        }
                        if (para.endsWith("%")) {
                            if (m == 5) {
                                map.put("use_rate", para);
                                log.info("已用空间%：" + para);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                log.error("error!!!" + e.getMessage(), e);
            } finally {
                assert in != null;
                in.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
            log.error("error!!!" + e.getMessage(), e);
        }
        return map;
    }

    /**
     * K--查看硬盘空间大小
     */
    private static Map<String, Object> getLinuxDiskInfo(String path) {
        Map<String, Object> map = new HashMap<>(5);
        try {
            Runtime rt = Runtime.getRuntime();
            // df -k 查看硬盘空间
            Process p = rt.exec("df -k " + path);
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(
                        p.getInputStream()));
                String str = null;
                String[] strArray = null;
                int line = 0;
                while ((str = in.readLine()) != null) {
                    line++;
                    if (line != 2) {
                        continue;
                    }
                    int m = 0;
                    strArray = str.split(" ");
                    for (String para : strArray) {
                        if (para.trim().length() == 0) {
                            continue;
                        }
                        ++m;
                        // 目前的服务器
                        if (m == 4) {
                            Long spaceSize = getSpaceSize(para);
                            map.put("free", spaceSize);
                            log.info("可用空间大小：" + para + "k------>" + spaceSize + "b");
                        }
                        if (para.endsWith("%")) {
                            if (m == 5) {
                                map.put("use_rate", para);
                                log.info("已用空间%：" + para);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                log.error("error!!!" + e.getMessage(), e);
            } finally {
                assert in != null;
                in.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
            log.error("error!!!" + e.getMessage(), e);
        }
        return map;
    }

    /**
     * 判断是否为linux系统
     */
    private static boolean isLinux() {
        return System.getProperty("os.name").toLowerCase().contains("linux");
    }

    /**
     * 判断是否为window系统
     */
    private static boolean isWindow() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    /**
     * 获取空间大小 单位：g--->b
     */
    private static Long getSpaceSizeByG(String para) {
        String spaceUnit = para.substring(0, para.indexOf("G"));
        long size = Long.parseLong(spaceUnit);
        return size * 1024 * 1024 * 1024;
    }

    /**
     * 获取空间大小 单位：k--->b
     */
    private static Long getSpaceSize(String para) {
        long size = Long.parseLong(para);
        return size * 1024;
    }


}
