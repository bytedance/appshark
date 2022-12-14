package com.blingsec.app_shark.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import lombok.Data;

import ch.ethz.ssh2.ChannelCondition;
import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;
import org.apache.tomcat.util.http.fileupload.IOUtils;

public class RemoteShellExecutor {

    private Connection conn;
    /** 远程机器IP */
    private String ip;
    /** 用户名 */
    private String osUsername;
    /** 密码 */
    private String password;
    private String charset = Charset.defaultCharset().toString();

    private static final String GET_SHELL_PID = "ps -ef | grep '%s' | grep -v grep |awk '{print $2}'";

    private static final String KILL_SHELL_PID = "kill -15 %s";

    private static final int TIME_OUT = 1000 * 5 * 60;

    /**
     * 构造函数
     * @param ip
     * @param usr
     * @param pasword
     */
    public RemoteShellExecutor(String ip, String usr, String pasword) {
        this.ip = ip;
        this.osUsername = usr;
        this.password = pasword;
    }


    /**
     * 登录
     * @return
     * @throws IOException
     */
    private boolean login() throws IOException {
        conn = new Connection(ip);
        conn.connect();
        return conn.authenticateWithPassword(osUsername, password);
    }

    /**
     * 执行脚本
     *
     * @param cmds
     * @return
     * @throws Exception
     */
    public ExecuteResultVO exec(String cmds) throws Exception {
        InputStream stdOut = null;
        InputStream stdErr = null;
        ExecuteResultVO executeResultVO = new ExecuteResultVO();
        String outStr = "";
        String outErr = "";
        int ret = -1;
        try {
            if (login()) {
                // Open a new {@link Session} on this connection
                Session session = conn.openSession();
                // Execute a command on the remote machine.
                session.execCommand(cmds);

                stdOut = new StreamGobbler(session.getStdout());
                outStr = processStream(stdOut, charset);

                stdErr = new StreamGobbler(session.getStderr());
                outErr = processStream(stdErr, charset);

                session.waitForCondition(ChannelCondition.EXIT_STATUS, TIME_OUT);

                System.out.println("outStr=" + outStr);
                System.out.println("outErr=" + outErr);

                ret = session.getExitStatus();
                executeResultVO.setOutStr(outStr);
                executeResultVO.setOutErr(outErr);

            } else {
                throw new Exception("登录远程机器失败" + ip); // 自定义异常类 实现略
            }
        } finally {
            if (conn != null) {
                conn.close();
            }
            IOUtils.closeQuietly(stdOut);
            IOUtils.closeQuietly(stdErr);
        }
        return executeResultVO;
    }

    /**
     * @param in
     * @param charset
     * @return
     * @throws IOException
     * @throws UnsupportedEncodingException
     */
    private String processStream(InputStream in, String charset) throws Exception {
        byte[] buf = new byte[1024];
        StringBuilder sb = new StringBuilder();
        int len = 0;
        while ((len=in.read(buf)) != -1) {
            sb.append(new String(buf,0,len, charset));
        }
        return sb.toString();
    }

    public static void main(String args[]) throws Exception {
        //调远程shell
        /*RemoteShellExecutor executor = new RemoteShellExecutor("81.69.7.178", "ubuntu", "Blkj.123");
        String cmd = "sudo password root;"
               +"cd /root/appshark";*/
        RemoteShellExecutor executor = new RemoteShellExecutor("81.69.7.178", "root", "root");
        String cmd = "cd /root/appshark;" +
                "ll";
        RemoteShellExecutor.ExecuteResultVO exec = executor.exec(cmd);
        System.out.println(exec.toString());

    }

    @Data
    public class ExecuteResultVO<T>{
        private String outStr;
        private String outErr;
        //省略get set
    }
}
