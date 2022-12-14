package com.blingsec.app_shark.controller;


import cn.hutool.core.collection.CollectionUtil;
import com.alibaba.fastjson.JSON;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.blingsec.app_shark.pojo.dto.FileInFo;
import com.blingsec.app_shark.service.FileInfoService;
import com.blingsec.app_shark.util.DiskUtil;
import com.blingsec.app_shark.util.FileUtil;
import com.google.common.collect.Lists;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/file")
public class FileInfoController {
    private static final Logger logger = LoggerFactory.getLogger(FileInfoController.class);
    public static final String ROOT_APPSHARK = "/root/appshark";
    //在文件操作中，不用/或者\最好，推荐使用File.separator
    private final static String fileDir = File.separator + "apps" + File.separator + "files" + File.separator;
    private final static String rootPath = ROOT_APPSHARK + fileDir;

    private final static String fileRulesDir = File.separator + "config" + File.separator + "rules" + File.separator;
    private final static String rootRulesPath = System.getProperty("user.dir") + fileRulesDir;
    private static final List<String> BLACK_LIST = Lists.newArrayList(
            "../",
            "./",
            "*",
            "/",
            "~/",
            " "
    );
    @Autowired
    private FileInfoService fileInfoService;

    private static long numBToGB(long num) {
        //字节转成g
        return num / 1024 / 1024 / 1024;
    }

    /**
     * 上传文件
     *
     * @return ResultEntity
     */
    @RequestMapping("/upload")
    public ResultEntity uploadFile(@RequestParam("file") MultipartFile file) {
        logger.info("******文件上传开始******");
        ResultEntity resultEntity;
        //获取文件路径
        File fileDirs = new File(rootPath);
        logger.info("路径：----" + fileDirs);
        //是否存在
        if (!fileDirs.exists() && !fileDirs.isDirectory()) {
            fileDirs.mkdirs();
        }
        //获取文件大小判断是否该文件是可用空间
        long fileSize = file.getSize();
        Map<String, Object> diskInfo = DiskUtil.getDiskInfo(rootPath);
        logger.info("硬盘空间信息" + diskInfo);

        if (CollectionUtil.isEmpty(diskInfo)) {
            return ResultEntity.error("未查到硬盘空间信息");
        }
        long free = (long) diskInfo.get("free");
        if (fileSize < 0 || fileSize > free) {
            logger.error("硬盘空间不足,文件大小为：fileSize=>" + fileSize + "，磁盘可用空间大小为：fileDirsSize=>" + free);
            return ResultEntity.error("硬盘空间不足");
        }
        //是否存在
        if (!fileDirs.exists() && !fileDirs.isDirectory()) {
            fileDirs.mkdirs();
        }
        resultEntity = fileInfoService.saveUploadFile(file, rootPath, fileDir, false);
        logger.info("文件上传返回信息：" + JSON.toJSONString(resultEntity));
        logger.info("******文件上传结束******");
        return resultEntity;
    }

    /**
     * 上传文件
     *
     * @return ResultEntity
     */
    @RequestMapping("/uploadApp")
    public ResultEntity uploadApp(@RequestParam("file") MultipartFile file) {
        logger.info("******Apk文件上传开始******");
        ResultEntity resultEntity;
        //获取文件路径
        File fileDirs = new File(rootPath);
        logger.info("路径：----" + fileDirs);
        //是否存在
        if (!fileDirs.exists() && !fileDirs.isDirectory()) {
            fileDirs.mkdirs();
        }
        //获取文件大小判断是否该文件是可用空间
        long fileSize = file.getSize();
        Map<String, Object> diskInfo = DiskUtil.getDiskInfo(rootPath);
        logger.info("硬盘空间信息" + diskInfo);

        if (CollectionUtil.isEmpty(diskInfo)) {
            return ResultEntity.error("未查到硬盘空间信息");
        }
        long free = (long) diskInfo.get("free");
        if (fileSize < 0 || fileSize > free) {
            logger.error("硬盘空间不足,文件大小为：fileSize=>" + fileSize + "，磁盘可用空间大小为：fileDirsSize=>" + free);
            return ResultEntity.error("硬盘空间不足");
        }
        //是否存在
        if (!fileDirs.exists() && !fileDirs.isDirectory()) {
            fileDirs.mkdirs();
        }
        resultEntity = fileInfoService.uploadApp(file, rootPath, fileDir);
        logger.info("文件上传返回信息：" + JSON.toJSONString(resultEntity));
        logger.info("******Apk文件上传开始结束******");
        return resultEntity;
    }

    @RequestMapping("/uploadRules")
    public ResultEntity uploadRulesFile(@RequestParam("file") MultipartFile file) {
        logger.info("******文件上传开始******");
        ResultEntity resultEntity;
        //获取文件路径
        File fileDirs = new File(rootRulesPath);
        logger.info("路径：----" + fileDirs);
        //是否存在
        if (!fileDirs.exists() && !fileDirs.isDirectory()) {
            fileDirs.mkdirs();
        }
        //获取文件大小判断是否该文件是可用空间
        long fileSize = file.getSize();
        Map<String, Object> diskInfo = DiskUtil.getDiskInfo(rootRulesPath);
        logger.info("硬盘空间信息" + diskInfo);

        if (CollectionUtil.isEmpty(diskInfo)) {
            return ResultEntity.error("未查到硬盘空间信息");
        }
        long free = (long) diskInfo.get("free");
        if (fileSize < 0 || fileSize > free) {
            logger.error("硬盘空间不足,文件大小为：fileSize=>" + fileSize + "，磁盘可用空间大小为：fileDirsSize=>" + free);
            return ResultEntity.error("硬盘空间不足");
        }
        //是否存在
        if (!fileDirs.exists() && !fileDirs.isDirectory()) {
            fileDirs.mkdirs();
        }
        resultEntity = fileInfoService.saveUploadFile(file, rootRulesPath, fileDir, true);
        logger.info("文件上传返回信息：" + JSON.toJSONString(resultEntity));
        logger.info("******文件上传结束******");
        return resultEntity;
    }
    /**
     * 下载文件
     *
     * @return ResultEntity
     */
    @RequestMapping("/download")
    public ResultEntity download(HttpServletRequest request, HttpServletResponse response, @RequestBody FileData uploadFile) {
        logger.info("******文件下载开始******");
        String fileName = uploadFile.getFileName();
        BLACK_LIST.forEach(blackName -> {
            int i = fileName.indexOf(blackName);
            if (i >= 0) {
                throw new BusinessException("非法操作");
            }
        });
        ResultEntity resultEntity;
        //通过文件的保存文件夹路径加上文件的名字来获得文件
        File file = new File(rootPath, fileName);
        if (!fileName.isEmpty()) {
            //当文件存在
            if (file.exists()) {
                resultEntity = fileInfoService.getDownLoad(request, response, fileName, file);
            } else {
                return ResultEntity.FILE_INFO_DOWNLOAD;
            }
        } else {
            return ResultEntity.FILE_INFO_DOWNLOAD;
        }
        logger.info("文件下载返回信息：" + JSON.toJSONString(resultEntity));
        logger.info("******文件下载结束******");
        return resultEntity;
    }

    /**
     * 下载文件
     *
     * @return ResultEntity
     */
    @PostMapping(value = "/downloadById/{fileId}", produces = "application/json;charset=UTF-8")
    public ResultEntity downloadById(HttpServletRequest request, HttpServletResponse response, @PathVariable Long fileId) {
        logger.info("******文件下载开始******");
        if (fileId == null || fileId <= 0) {
            return ResultEntity.FILE_INFO_DOWNLOAD;
        }
        ResultEntity resultEntity;
        FileInFo fileInFo = fileInfoService.findById(fileId);
        if (fileInFo == null) {
            return ResultEntity.FILE_INFO_DOWNLOAD;
        }
        String fileName = fileInFo.getFileNameNew();
        //通过文件的保存文件夹路径加上文件的名字来获得文件
        File file = new File(rootPath, fileName);
        if (!fileName.isEmpty()) {
            //当文件存在
            if (file.exists()) {
                resultEntity = fileInfoService.getDownLoad(request, response, fileName, file);
            } else {
                return ResultEntity.FILE_INFO_DOWNLOAD;
            }
        } else {
            return ResultEntity.FILE_INFO_DOWNLOAD;
        }
        logger.info("文件下载返回信息：" + JSON.toJSONString(resultEntity));
        logger.info("******文件下载结束******");
        return resultEntity;
    }

    @PostMapping("/getFileById/{fileId}")
    public File getFileById(@PathVariable(value = "fileId") Long fileId) {
        FileInFo fileInFo = fileInfoService.findById(fileId);
        if (fileInFo != null) {
            String fileName = fileInFo.getFileNameNew();
            File file = new File(rootPath, fileName);
            //当文件存在
            if (file.exists()) {
                return file;
            }
        }
        return null;
    }

    @PostMapping(value = "/downloadFileById/{fileId}", produces = "application/json;charset=UTF-8")
    public void downloadFileById(@PathVariable Long fileId, HttpServletResponse response) throws IOException {
        logger.info("******文件下载开始******");
        FileInFo fileInFo = fileInfoService.findById(fileId);
        if (fileInFo != null) {
            String fileName = fileInFo.getFileNameNew();
            File file = new File(rootPath, fileName);
            //当文件存在
            if (file.exists()) {
                FileUtil.fileDownload(response, file, false);
            }
        }
    }

    @PostMapping(value = "/findFileById/{fileId}", produces = "application/json;charset=UTF-8")
    public FileInFo findFileById(@PathVariable Long fileId) {
        return fileInfoService.findById(fileId);
    }

    @PostMapping(value = "/readFileByName", produces = "application/json;charset=UTF-8")
    public ResultEntity readFileByName(@RequestBody FileDto dto) {
        logger.info("******文件读取开始******");
        File file = new File(rootPath, dto.getFileName());
        if (!file.exists()) {
            logger.error("******文件读取开始失败, 未找到文件******");
            return ResultEntity.ERROR;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line.replaceAll("\t", "").replaceAll("\n", ""));
            }
            return ResultEntity.success(builder);
        } catch (Exception ex) {
            logger.error("******文件读取开始失败******", ex);
        }
        return ResultEntity.ERROR;
    }

    @RequestMapping("findByIdIn")
    @ResponseBody
    public List<FileDto> findByIdIn(@RequestBody List<Integer> list) {
        return fileInfoService.findByIdIn(list);
    }

    /**
     * 下载文件
     */
    @PostMapping(value = "/downloadByName", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public void downloadByName(HttpServletResponse response, @RequestBody FileDto dto) throws IOException {
        //通过文件的保存文件夹路径加上文件的名字来获得文件
        File file = new File(rootPath, dto.getFileName());
        if (file.exists()) {
            FileUtil.fileDownload(response, file, false);
        }
    }
}

@Data
class FileData {
    private String fileName;
}