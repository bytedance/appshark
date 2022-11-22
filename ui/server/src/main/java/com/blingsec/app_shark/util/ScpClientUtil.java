package com.blingsec.app_shark.util;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.util
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月08日 16:18
 * -------------- -------------- ---------------------
 */

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.SCPClient;

import java.io.IOException;

/**
 * 下载和上传文件
 */
public class ScpClientUtil {

    private String ip;
    private int port;
    private String username;
    private String password;

    static private ScpClientUtil instance;

    static synchronized public ScpClientUtil getInstance(String ip, int port, String username, String passward) {
        if (instance == null) {
            instance = new ScpClientUtil(ip, port, username, passward);
        }
        return instance;
    }

    public ScpClientUtil(String ip, int port, String username, String passward) {
        this.ip = ip;
        this.port = port;
        this.username = username;
        this.password = passward;
    }

    public void getFile(String remoteFile, String localTargetDirectory) {
        Connection conn = new Connection(ip, port);
        try {
            conn.connect();
            boolean isAuthenticated = conn.authenticateWithPassword(username, password);
            if (!isAuthenticated) {
                System.err.println("authentication failed");
            }
            SCPClient client = new SCPClient(conn);
            client.get(remoteFile, localTargetDirectory);
        } catch (IOException ex) {
            ex.printStackTrace();
        }finally{
            conn.close();
        }
    }

    public void putFile(String localFile, String remoteTargetDirectory) {
        putFile(localFile, null, remoteTargetDirectory);
    }

    public void putFile(String localFile, String remoteFileName, String remoteTargetDirectory) {
        putFile(localFile, remoteFileName, remoteTargetDirectory,null);
    }

    public void putFile(String localFile, String remoteFileName, String remoteTargetDirectory, String mode) {
        Connection conn = new Connection(ip, port);
        try {
            conn.connect();
            boolean isAuthenticated = conn.authenticateWithPassword(username, password);
            if (!isAuthenticated) {
                System.err.println("authentication failed");
            }
            SCPClient client = new SCPClient(conn);
            if ((mode == null) || (mode.length() == 0)) {
                mode = "0600";
            }
            if (remoteFileName == null) {
                client.put(localFile, remoteTargetDirectory);
            } else {
                client.put(localFile, remoteFileName, remoteTargetDirectory, mode);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }finally{
            conn.close();
        }
    }

    public static void main(String[] args) {
        ScpClientUtil scpClient = ScpClientUtil.getInstance("81.69.7.178",22, "root", "root");
        // 从远程服务器/opt下的index.html下载到本地项目根路径下
        scpClient.getFile("/root/appshark/out/result.json","./");
        // 把本地项目下根路径下的index.html上传到远程服务器/opt目录下
//        scpClient.putFile("./index.html","/opt");
    }
}
