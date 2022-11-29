package com.blingsec.app_shark.service.impl;


import cn.hutool.crypto.SecureUtil;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.mapper.FileInfoDao;
import com.blingsec.app_shark.pojo.ResultEntity;
import com.blingsec.app_shark.pojo.dto.FileDto;
import com.blingsec.app_shark.pojo.dto.FileInFo;
import com.blingsec.app_shark.service.FileInfoService;
import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.apache.tomcat.util.http.fileupload.util.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Service
public class FileInfoServiceImpl implements FileInfoService {
    @Autowired
    private FileInfoDao fileInfoDao;
    public static final String JSON = "json";
    private static final List<String> WHITE_LIST = Lists.newArrayList(
            "xls",
            "xlsm",
            "xltx",
            "xltm",
            JSON,
            "docx",
            "docm",
            "doc",
            "dotx",
            "dotm",
            "dot",
            "pdf",
            "xlsx",
            "xps",
            "mht",
            "mhtml",
            "htm",
            "html",
            "rtf",
            "txt",
            "xml",
            "ppt",
            "pptx",
            "tif",
            "jpg",
            "zip",
            "7z",
            "rar",
            "png",
            "apk",
            "ipa"
    );
    private static final Logger logger = LoggerFactory.getLogger(FileInfoServiceImpl.class);

    @Override
    public ResultEntity saveUploadFile(MultipartFile file, String rootPath, String fileDir, boolean isRules) {
        //具体业务实现
        try {
            //获取文件信息
            String originalFile = file.getOriginalFilename();
            if (originalFile == null) {
                return ResultEntity.error("上传文件为空");
            }
            String originalFilename = new String(originalFile.getBytes(StandardCharsets.UTF_8));
            //截取.文件原名称
            String beforeLast = StringUtils.substringBeforeLast(originalFilename, ".");
            //加密后的文件名称
            String beforeLastMd5 = SecureUtil.md5(beforeLast + System.currentTimeMillis());
            //截取点之后的的
            String suffix = StringUtils.substringAfterLast(originalFilename, ".");
            if (!WHITE_LIST.contains(suffix)) {
                throw new BusinessException("不支持的文件格式");
            }
            if (isRules && !JSON.equals(suffix)) {
                throw new BusinessException("不支持的文件格式");
            }
            String fileNameNew = beforeLastMd5 + "." + suffix;
            if (isRules) {
                fileNameNew = originalFilename;
            }
            //保存的路径--实际存储路径
            String storagePath = rootPath + fileNameNew;
            logger.debug("上传的文件：" + file.getName() + "," + file.getContentType() + "," + originalFilename
                    + "，保存的路径为：" + storagePath);
            Streams.copy(file.getInputStream(), new FileOutputStream(storagePath), true);
            //或者下面的
            InputStream inputStream = file.getInputStream();
            FileOutputStream outputStream = new FileOutputStream(storagePath);
            IOUtils.copy(inputStream, outputStream);
            outputStream.close();
//            Path path = Paths.get(storagePath);
//            Files.write(path, file.getBytes());
            FileInFo fileInFo = new FileInFo();
            fileInFo.setFileType(file.getContentType());
            fileInFo.setFileNameOld(originalFilename);
            fileInFo.setFileNameNew(fileNameNew);
            fileInFo.setFileStorgePath(fileDir + fileNameNew);
            Date date = new Date();
            fileInFo.setCtime(date);
            fileInFo.setMtime(date);
            if (!isRules) {
                int saveResInt = fileInfoDao.insertFileInfo(fileInFo);

//            file = null;
//            System.gc();//手动调用GC
                if (saveResInt > 0) {
                    return ResultEntity.success(fileInFo);
                } else {
                    return ResultEntity.FILE_INFO_UPLOAD;
                }
            } else {
                return ResultEntity.SUCCESS;
            }
        } catch (IOException e) {
            logger.debug("错误信息---" + e);
            return ResultEntity.ERROR;
        }
    }

    @Override
    public ResultEntity getDownLoad(HttpServletRequest request, HttpServletResponse response, String fileName, File file) {
        //首先设置响应的内容格式是force-download，那么你一旦点击下载按钮就会自动下载文件了
        String type = request.getServletContext().getMimeType(fileName);
        response.setContentType(type);
        //通过设置头信息给文件命名，也即是，在前端，文件流被接受完还原成原文件的时候会以你传递的文件名来命名
        response.addHeader("Content-Disposition", "attachment; filename=" + file.getName());
        try {
            org.apache.commons.io.IOUtils.copy(new FileInputStream(file), response.getOutputStream());
        } catch (IOException e) {
            logger.error("文件下载发生错误" + e);
            return ResultEntity.ERROR;
        }
        return null;
    }

    @Override
    public List<FileDto> findByIdIn(List<Integer> list) {
        List<FileInFo> files = fileInfoDao.findByIdIn(list);
        List<FileDto> result = Lists.newArrayList();
        for (FileInFo file : files) {
            FileDto dto = new FileDto();
            dto.setFileId(file.getFileId());
            dto.setFileName(file.getFileNameOld());
            dto.setFileUrl(file.getFileStorgePath());
            dto.setFileNameNew(file.getFileNameNew());
            result.add(dto);
        }
        return result;
    }

    @Override
    public FileInFo findById(Long fileId) {
        return fileInfoDao.findById(fileId);
    }

    @Override
    public ResultEntity uploadApp(MultipartFile file, String rootPath, String fileDir) {
        //具体业务实现
        try {
            //获取文件信息
            String originalFile = file.getOriginalFilename();
            if (originalFile == null) {
                return ResultEntity.error("上传文件为空");
            }
            String originalFilename = new String(originalFile.getBytes(StandardCharsets.UTF_8));
            //截取.文件原名称
            String beforeLast = StringUtils.substringBeforeLast(originalFilename, ".");
            //加密后的文件名称
            String beforeLastMd5 = SecureUtil.md5(beforeLast + System.currentTimeMillis());
            //截取点之后的的
            String suffix = StringUtils.substringAfterLast(originalFilename, ".");
            if (!"apk".equals(suffix)) {
                throw new BusinessException("仅支持上传apk格式文件");
            }
            String fileNameNew = beforeLastMd5 + "." + suffix;
            //保存的路径--实际存储路径
            String storagePath = rootPath + originalFilename;
            logger.debug("上传的文件：" + file.getName() + "," + file.getContentType() + "," + originalFilename
                    + "，保存的路径为：" + storagePath);
            Streams.copy(file.getInputStream(), new FileOutputStream(storagePath), true);
            //或者下面的
            InputStream inputStream = file.getInputStream();
            FileOutputStream outputStream = new FileOutputStream(storagePath);
            IOUtils.copy(inputStream, outputStream);
            outputStream.close();
//            Path path = Paths.get(storagePath);
//            Files.write(path, file.getBytes());
            FileInFo fileInFo = new FileInFo();
            fileInFo.setFileType(file.getContentType());
            fileInFo.setFileNameOld(originalFilename);
            fileInFo.setFileNameNew(fileNameNew);
            fileInFo.setFileStorgePath(fileDir + fileNameNew);
            Date date = new Date();
            fileInFo.setCtime(date);
            fileInFo.setMtime(date);
            int saveResInt = fileInfoDao.insertFileInfo(fileInFo);

//            file = null;
//            System.gc();//手动调用GC
            if (saveResInt > 0) {
                return ResultEntity.success(fileInFo);
            } else {
                return ResultEntity.FILE_INFO_UPLOAD;
            }
        } catch (IOException e) {
            logger.debug("错误信息---" + e);
            return ResultEntity.ERROR;
        }
    }
}
