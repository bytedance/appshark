package com.blingsec.app_shark.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.util.Objects;

public class FileUtil {
    private static final Logger logger = LoggerFactory.getLogger(FileUtil.class);

    /**
     * 将指定文件对象写入到特定的Servlet响应对象，进而实现下载
     * 一般用于下载已经存在的文件
     *
     * @param response         目标Servlet响应对象
     * @param file             要下载的文件对象
     * @param isDeleteOriginal 是否删除服务器文件原本，true下载后将删除服务器上的文件
     */
    public static void fileDownload(HttpServletResponse response, File file, Boolean isDeleteOriginal) throws IOException {
        InputStream inputStream = null;
        BufferedInputStream bufferedInputStream = null;
        try {
            inputStream = new FileInputStream(file);

            bufferedInputStream = new BufferedInputStream(inputStream);

            response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(file.getName(), "UTF-8"));
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(response.getOutputStream());

            int length = 0;
            byte[] temp = new byte[1024 * 10];
            while ((length = bufferedInputStream.read(temp)) != -1) {
                bufferedOutputStream.write(temp, 0, length);
            }
            bufferedOutputStream.flush();
            bufferedOutputStream.close();

//            if (isDeleteOriginal) {
//                if (!file.delete()) {
//                    // file delete failed; take appropriate action
//                    logger.error("file delete failed;");
//                }
//            }
        } catch (FileNotFoundException e) {
            logger.error(e.getMessage(),e);
        } catch (IOException e) {
            logger.error(e.getMessage(),e);
        }finally {
            if (Objects.nonNull(bufferedInputStream)){
                bufferedInputStream.close();
            }
            if (Objects.nonNull(inputStream)){
                inputStream.close();
            }
        }
    }
}