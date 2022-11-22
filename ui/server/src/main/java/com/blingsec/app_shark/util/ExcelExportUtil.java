package com.blingsec.app_shark.util;

import cn.hutool.core.collection.CollectionUtil;
import com.blingsec.app_shark.common.exception.BusinessException;
import com.blingsec.app_shark.pojo.dto.ExcelExp;
import com.blingsec.app_shark.pojo.entity.AppSharkAppInfo;
import com.blingsec.app_shark.pojo.entity.AppSharkUsePermission;
import com.blingsec.app_shark.pojo.vo.AssignmentDetailVo;
import com.github.pagehelper.PageInfo;
import org.apache.commons.compress.utils.Lists;
import org.apache.poi.hssf.usermodel.*;
import org.apache.poi.hssf.util.HSSFColor;
import org.apache.poi.ss.usermodel.Color;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFColor;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.util.*;

/**
 * @Project : app_shark
 * @Package Name : com.blingsec.app_shark.util
 * @Description :
 * @Author : renxin
 * @Creation Date : 2022年10月21日 14:41
 * -------------- -------------- ---------------------
 */
public class ExcelExportUtil {
    private ExcelExportUtil (){}
    private static ExcelExportUtil excelExportUtil = null;
    static{
        /** 类加载时创建，只会创建一个对象 */
        if(excelExportUtil == null) excelExportUtil = new ExcelExportUtil ();
    }

    /**
     * @param @param file 导出文件路径
     * @param @param mysheets
     * @return void
     * @throws
     * @Title: exportManySheetExcel
     * @Description: 可生成单个、多个sheet
     */
    public static Workbook exportManySheetExcel(List<ExcelExp> mysheets) {
        HSSFWorkbook wb = new HSSFWorkbook();// 创建工作薄
        if (CollectionUtil.isEmpty(mysheets)){
            throw new BusinessException("数据不存在！");
        }
        List<ExcelExp> definedSheets = Lists.newArrayList();
        List<ExcelExp> undefinedSheets = Lists.newArrayList();
        for (int i = 0; i < mysheets.size(); i++) {
            ExcelExp excelExp = mysheets.get(i);
            if (excelExp.getDefinedStatus()){
                definedSheets.add(excelExp);
            }else {
                undefinedSheets.add(excelExp);
            }
        }
        populatedefinedSheets(wb,definedSheets);
        populateUndefinedSheets(wb,undefinedSheets);
        return wb;
    }

    private static void populatedefinedSheets(HSSFWorkbook wb, List<ExcelExp> definedSheets) {
        for (ExcelExp excel : definedSheets) {
            Map<String, Object> definedData = excel.getDefinedData();
            AssignmentDetailVo detail = (AssignmentDetailVo) definedData.get("detail");
            PageInfo<AppSharkUsePermission> appSharkUsePermissionPageInfo = (PageInfo<AppSharkUsePermission>) definedData.get("appSharkUsePermissionPageInfo");
            AppSharkAppInfo appSharkAppInfo = detail.getAppSharkAppInfo();
            // 新建一个sheet
            HSSFSheet sheet = wb.createSheet(excel.getFileName());// 获取该sheet名称
            HSSFPalette customPalette = wb.getCustomPalette();
            sheet.setColumnWidth(0,20*256);
            sheet.setColumnWidth(1,38*256);
            sheet.setColumnWidth(2,20*256);
            sheet.setColumnWidth(3,46*256);
            sheet.setColumnWidth(4,26*256);
            sheet.setColumnWidth(5,46*256);
            HSSFCellStyle titleStyle = wb.createCellStyle();
            // 设置单元格样式
            HSSFFont titleFont = wb.createFont(); // 标题字体
            titleFont.setFontName("等线");
            titleFont.setFontHeightInPoints((short) 14); // 字号
            byte[] bytes = hexColorToBytes(0x04B2F6);
            byte paletteIndex = 0x8;
            customPalette.setColorAtIndex(paletteIndex,bytes[0],bytes[1],bytes[2]);
            titleFont.setColor(paletteIndex);
            titleFont.setBold(true);
            titleStyle.setFont(titleFont);
            titleStyle.setAlignment(HorizontalAlignment.CENTER);

            HSSFCellStyle leftStyle = wb.createCellStyle();
            // 设置单元格样式
            HSSFFont leftFont = wb.createFont(); // 标题字体
            leftFont.setFontName("等线");
            leftFont.setFontHeightInPoints((short) 11); // 字号
            leftStyle.setFont(leftFont);
            leftStyle.setAlignment(HorizontalAlignment.RIGHT);

            HSSFCellStyle rightStyle = wb.createCellStyle();
            // 设置单元格样式
            HSSFFont rightFont = wb.createFont(); // 标题字体
            rightFont.setFontName("等线");
            rightFont.setFontHeightInPoints((short) 11); // 字号
            rightStyle.setFont(rightFont);
            rightStyle.setAlignment(HorizontalAlignment.LEFT);

            HSSFCellStyle bottomRightStyle = wb.createCellStyle();
            // 设置单元格样式
            HSSFFont bottomRightFont = wb.createFont(); // 标题字体
            bottomRightFont.setFontName("等线");
            bottomRightFont.setFontHeightInPoints((short) 11); // 字号
            bottomRightFont.setBold(true);
            bottomRightStyle.setFont(bottomRightFont);
            bottomRightStyle.setAlignment(HorizontalAlignment.CENTER);

            HSSFCellStyle bottomLeftStyle = wb.createCellStyle();
            // 设置单元格样式
            HSSFFont bottomLeftFont = wb.createFont(); // 标题字体
            bottomLeftFont.setFontName("等线");
            bottomLeftFont.setFontHeightInPoints((short) 11); // 字号
            bottomLeftStyle.setFont(bottomLeftFont);
            bottomLeftStyle.setAlignment(HorizontalAlignment.CENTER);

            // 第一行  任务基本信息
            HSSFRow row1 = sheet.createRow(0);
            HSSFCell cell1_0 = row1.createCell(0);
            sheet.addMergedRegion(new CellRangeAddress(0, 0, 0, 5));
            cell1_0.setCellStyle(titleStyle);
            // 设置单元格内容
            cell1_0.setCellValue("任务基本信息");
            //第二行  任务编号   任务名称
            HSSFRow row2 = sheet.createRow(1);
            HSSFCell cell2_0 = row2.createCell(0);
            cell2_0.setCellValue("任务编号");
            cell2_0.setCellStyle(leftStyle);
            HSSFCell cell2_1 = row2.createCell(1);
            cell2_1.setCellValue(detail.getGuid());
            cell2_1.setCellStyle(rightStyle);
            HSSFCell cell2_2 = row2.createCell(2);
            cell2_2.setCellValue("任务名称");
            cell2_2.setCellStyle(leftStyle);
            HSSFCell cell2_3 = row2.createCell(3);
            sheet.addMergedRegion(new CellRangeAddress(1, 1, 3, 5));
            cell2_3.setCellValue(detail.getAssignmentName());
            cell2_3.setCellStyle(rightStyle);
            //第三行  任务描述
            HSSFRow row3 = sheet.createRow(2);
            HSSFCell cell3_0 = row3.createCell(0);
            cell3_0.setCellValue("任务描述");
            cell3_0.setCellStyle(leftStyle);
            HSSFCell cell3_1 = row3.createCell(1);
            sheet.addMergedRegion(new CellRangeAddress(2, 2, 1, 5));
            cell3_1.setCellValue(detail.getAssignmentDescription());
            cell3_1.setCellStyle(rightStyle);
            //第四行  App文件
            HSSFRow row4 = sheet.createRow(3);
            HSSFCell cell4_0 = row4.createCell(0);
            cell4_0.setCellValue("App文件");
            cell4_0.setCellStyle(leftStyle);
            HSSFCell cell4_1 = row4.createCell(1);
            sheet.addMergedRegion(new CellRangeAddress(3, 3, 1, 5));
            cell4_1.setCellValue(detail.getAppAttach().getFileName());
            cell4_1.setCellStyle(rightStyle);
            //第五行  已选规则
            HSSFRow row5 = sheet.createRow(4);
            HSSFCell cell5_0 = row5.createCell(0);
            cell5_0.setCellValue("已选规则");
            cell5_0.setCellStyle(leftStyle);
            HSSFCell cell5_1 = row5.createCell(1);
            sheet.addMergedRegion(new CellRangeAddress(4, 4, 1, 5));
            cell5_1.setCellValue(detail.getRules());
            cell5_1.setCellStyle(rightStyle);
            //第六行  最大点分析时间     开始扫描时间   任务创建时间
            HSSFRow row6 = sheet.createRow(5);
            HSSFCell cell6_0 = row6.createCell(0);
            cell6_0.setCellValue("最大点分析时间");
            cell6_0.setCellStyle(leftStyle);
            HSSFCell cell6_1 = row6.createCell(1);
            cell6_1.setCellValue(detail.getLargestAnalysis() + "秒");
            cell6_1.setCellStyle(rightStyle);
            HSSFCell cell6_2 = row6.createCell(2);
            cell6_2.setCellValue("开始扫描时间");
            cell6_2.setCellStyle(leftStyle);
            HSSFCell cell6_3 = row6.createCell(3);
            cell6_3.setCellValue(DateUtil.date2String(detail.getScanTime(), DateUtil.DATE_TIME_SECOND_PATTERN));
            cell6_3.setCellStyle(rightStyle);
            HSSFCell cell6_4 = row6.createCell(4);
            cell6_4.setCellValue("任务创建时间");
            cell6_4.setCellStyle(leftStyle);
            HSSFCell cell6_5 = row6.createCell(5);
            cell6_5.setCellValue(DateUtil.date2String(detail.getCreatedAt(), DateUtil.DATE_TIME_SECOND_PATTERN));
            cell6_5.setCellStyle(rightStyle);
            //第七行  App基本信息
            HSSFRow row7 = sheet.createRow(6);
            HSSFCell cell7_0 = row7.createCell(0);
            sheet.addMergedRegion(new CellRangeAddress(6, 6, 0, 5));
            cell7_0.setCellStyle(titleStyle);
            cell7_0.setCellValue("App基本信息");
            //第八行  App名称
            HSSFRow row8 = sheet.createRow(7);
            HSSFCell cell8_0 = row8.createCell(0);
            cell8_0.setCellValue("App文件");
            cell8_0.setCellStyle(leftStyle);
            HSSFCell cell8_1 = row8.createCell(1);
            sheet.addMergedRegion(new CellRangeAddress(7, 7, 1, 5));
            cell8_1.setCellValue(appSharkAppInfo.getAppName());
            cell8_1.setCellStyle(rightStyle);
            //第九行  包名
            HSSFRow row9 = sheet.createRow(8);
            HSSFCell cell9_0 = row9.createCell(0);
            cell9_0.setCellValue("App文件");
            cell9_0.setCellStyle(leftStyle);
            HSSFCell cell9_1 = row9.createCell(1);
            sheet.addMergedRegion(new CellRangeAddress(8, 8, 1, 5));
            cell9_1.setCellValue(appSharkAppInfo.getPackageName());
            cell9_1.setCellStyle(rightStyle);
            //第十行  min_sdk   target_sdk  版本
            HSSFRow row10 = sheet.createRow(9);
            HSSFCell cell10_0 = row10.createCell(0);
            cell10_0.setCellValue("min_sdk");
            cell10_0.setCellStyle(leftStyle);
            HSSFCell cell10_1 = row10.createCell(1);
            cell10_1.setCellValue(appSharkAppInfo.getMinSdk());
            cell10_1.setCellStyle(rightStyle);
            HSSFCell cell10_2 = row10.createCell(2);
            cell10_2.setCellValue("target_sdk");
            cell10_2.setCellStyle(leftStyle);
            HSSFCell cell10_3 = row10.createCell(3);
            cell10_3.setCellValue(appSharkAppInfo.getTargetSdk());
            cell10_3.setCellStyle(rightStyle);
            HSSFCell cell10_4 = row10.createCell(4);
            cell10_4.setCellValue("版本");
            cell10_4.setCellStyle(leftStyle);
            HSSFCell cell10_5 = row10.createCell(5);
            cell10_5.setCellValue(appSharkAppInfo.getVersionName());
            cell10_5.setCellStyle(rightStyle);
            //第十一行  App权限清单
            HSSFRow row11 = sheet.createRow(10);
            HSSFCell cell11_0 = row11.createCell(0);
            sheet.addMergedRegion(new CellRangeAddress(10, 10, 0, 5));
            cell11_0.setCellStyle(titleStyle);
            cell11_0.setCellValue("App权限清单");
            //第十二行  权限名称  释义
            HSSFRow row12 = sheet.createRow(11);
            HSSFCell cell12_0 = row12.createCell(0);
            sheet.addMergedRegion(new CellRangeAddress(11, 11, 0, 2));
            cell12_0.setCellValue("权限名称");
            cell12_0.setCellStyle(bottomRightStyle);
            HSSFCell cell12_1 = row12.createCell(3);
            sheet.addMergedRegion(new CellRangeAddress(11, 11, 3, 5));
            cell12_1.setCellValue("释义");
            cell12_1.setCellStyle(bottomRightStyle);
            //第十三行  遍历权限清单
            List<AppSharkUsePermission> appSharkUsePermissions = appSharkUsePermissionPageInfo.getList();
            if (CollectionUtil.isNotEmpty(appSharkUsePermissions)){
                for (int i = 0; i < appSharkUsePermissions.size(); i++) {
                    int i1 = 12 + i;
                    AppSharkUsePermission appSharkUsePermission = appSharkUsePermissions.get(i);
                    HSSFRow row13 = sheet.createRow(i1);
                    HSSFCell row14_0 = row13.createCell(0);
                    sheet.addMergedRegion(new CellRangeAddress(i1, i1, 0, 2));
                    row14_0.setCellValue(appSharkUsePermission.getName());
                    row14_0.setCellStyle(bottomLeftStyle);
                    HSSFCell cell14_1 = row13.createCell(3);
                    sheet.addMergedRegion(new CellRangeAddress(i1, i1, 3, 5));
                    cell14_1.setCellValue(appSharkUsePermission.getParaphrase());
                    cell14_1.setCellStyle(bottomLeftStyle);
                }
            }
        }
    }

    private static void populateUndefinedSheets(HSSFWorkbook wb, List<ExcelExp> undefinedSheets) {
        HSSFPalette customPalette = wb.getCustomPalette();
        // 表头样式
        HSSFCellStyle titleStyle = wb.createCellStyle();
        // 设置单元格样式
        HSSFFont titleFont = wb.createFont(); // 标题字体
        titleFont.setFontName("等线");
        titleFont.setFontHeightInPoints((short) 14); // 字号
        byte[] bytes = hexColorToBytes(0x04B2F6);
        byte paletteIndex = 0x8;
        customPalette.setColorAtIndex(paletteIndex,bytes[0],bytes[1],bytes[2]);
        titleFont.setColor(paletteIndex);
        titleFont.setBold(true);
        titleStyle.setFont(titleFont);
        titleStyle.setAlignment(HorizontalAlignment.CENTER);

        HSSFCellStyle sequenceStyle = wb.createCellStyle();
        sequenceStyle.setAlignment(HorizontalAlignment.CENTER);
        // fontStyle.setBoldweight(HSSFFont.BOLDWEIGHT_BOLD);
        for (ExcelExp excel : undefinedSheets) {
            int i1 = undefinedSheets.indexOf(excel);
            // 新建一个sheet
            HSSFSheet sheet1 = wb.createSheet(excel.getFileName());// 获取该sheet名称
            sheet1.setColumnWidth(0,20*256);
            sheet1.setColumnWidth(1,20*256);
            if (i1==0){
                sheet1.setColumnWidth(2,150*256);
                sheet1.setColumnWidth(3,150*256);
            }else {
                sheet1.setColumnWidth(2,20*256);
                sheet1.setColumnWidth(3,20*256);
            }
            sheet1.setColumnWidth(4,140*256);
            sheet1.setColumnWidth(5,100*256);
            sheet1.setColumnWidth(6,100*256);
            sheet1.setColumnWidth(7,100*256);
            sheet1.setColumnWidth(8,100*256);
            sheet1.setColumnWidth(9,100*256);
            sheet1.setColumnWidth(10,100*256);
            List<String> handers = excel.getHanders();// 获取sheet的标题名
            HSSFRow rowFirst = sheet1.createRow(0);// 第一个sheet的第一行为标题
            // 写标题
            for (int i = 0; i < handers.size(); i++) {
                // 获取第一行的每个单元格
                HSSFCell cell = rowFirst.createCell(i);
                // 往单元格里写数据
                cell.setCellValue(handers.get(i));
                cell.setCellStyle(titleStyle); // 加样式
            }
            // 写数据集
            List<List<String>> dataset = excel.getDataset();
            for (int i = 0; i < dataset.size(); i++) {
                List<String> data = dataset.get(i);// 获取该对象
                // 创建数据行
                HSSFRow row = sheet1.createRow(i + 1);
                for (int j = 0; j < data.size(); j++) {
                    // 设置对应单元格的值
                    HSSFCell cell = row.createCell(j);
                    cell.setCellValue(data.get(j));
                    if (j==0){
                        cell.setCellStyle(sequenceStyle);
                    }
                }
            }
        }
    }

    public static void outputXls(Workbook workbook, String fileName, HttpServletResponse response,
                                 HttpServletRequest request) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            workbook.write(os);
            byte[] content = os.toByteArray();
            InputStream is = new ByteArrayInputStream(content);
            // 设置response参数，可以打开下载页面
            response.reset();
            response.setContentType("application/vnd.ms-excel;charset=utf-8");
            response.setHeader("Content-Disposition",
                    "attachment;filename=" + encodeFileName(fileName + ".xls", request));
            ServletOutputStream out = response.getOutputStream();
            BufferedInputStream bis = null;
            BufferedOutputStream bos = null;
            try {
                bis = new BufferedInputStream(is);
                bos = new BufferedOutputStream(out);
                byte[] buff = new byte[2048];
                int bytesRead;
                // Simple read/write loop.
                while (-1 != (bytesRead = bis.read(buff, 0, buff.length))) {
                    bos.write(buff, 0, bytesRead);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (bis != null)
                    bis.close();
                if (bos != null)
                    bos.close();
            }
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    public static String encodeFileName(String fileName, HttpServletRequest request)
            throws UnsupportedEncodingException {
        String agent = request.getHeader("USER-AGENT");
        if (null != agent && -1 != agent.indexOf("MSIE")) {
            return URLEncoder.encode(fileName, "UTF-8");
        } else if (null != agent && -1 != agent.indexOf("Mozilla")) {
            return "=?UTF-8?B?"
                    + (new String(org.apache.commons.codec.binary.Base64.encodeBase64(fileName.getBytes("UTF-8")))) + "?=";
        } else {
            return fileName;
        }
    }

    /**
     * 把list<map>封装成list<String[]> 由于我的结果集是List<Map<String,Object>>,所以我写了这个个方法,把它转换成List<String[]>
     *
     * @param list   要封装的list
     * @param strKey String[]的长度
     * @return
     */
    public static List<String[]> listUtils(List<Map<String, Object>> list, String[] strKey) {

        if (list != null && list.size() > 0) {// 如果list有值

            List<String[]> strList = new ArrayList<String[]>();// 实例化一个list<string[]>

            for (Map<String, Object> map : list) {// 遍历数组

                String[] str = new String[strKey.length];// 实力一个string[]

                Integer count = 0;// 作为str的下标,每次从0开始

                for (String s : strKey) {// 遍历map中的key
                    if (map.get(s) != null) {
                        str[count] = map.get(s).toString();
                    } else {
                        str[count] = "";
                    }
                    // 把map的value赋值到str数组中
                    count++;// str的下标+1
                }

                if (str != null) {// 如果str有值,添加到strList
                    strList.add(str);
                }
            }
            if (strList != null && strList.size() > 0) {// 如果strList有值,返回strList
                return strList;
            }
        }
        return null;
    }

    public static void main1(String[] args) {
        String a = "杨1,aaa";
        a.replace(",",String.valueOf((char)10));
        /** 第一页数据 */
        List<List<String>> dataAllOne = new ArrayList<>();
        List<String> data1 = Arrays.asList("杨1(char)10aaa","18", "男");
        List<String> data2 = Arrays.asList("杨2", "19", "女");
        dataAllOne.add(data1);
        dataAllOne.add(data2);
        /** 第二页数据 */
        List<List<String>> dataAllTwo = new ArrayList<>();
        List<String> data3 = Arrays.asList("驾照", "2022年9月5日10:08:46", "是");
        List<String> data4 = Arrays.asList("户口本", "2022-9-5 10:09:01", "否");
        dataAllTwo.add(data3);
        dataAllTwo.add(data4);

        ArrayList<ExcelExp> list = new ArrayList<>();
        ExcelExp excelExp1 = new ExcelExp("存放人员信息", Arrays.asList("姓名", "年龄", "性别"), dataAllOne,false);
        ExcelExp excelExp2 = new ExcelExp("存放文件信息", Arrays.asList("文件名称", "上传时间", "是否上传到FDFS"), dataAllTwo,false);
        list.add(excelExp1);
        list.add(excelExp2);
        Workbook workbook = exportManySheetExcel(list);

        //导出数据到excel
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("C:/root/demo.xls");
            workbook.write(fileOutputStream);
            fileOutputStream.flush();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(fileOutputStream != null){
                try {
                    fileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) {
        List<String> data1 = Arrays.asList("杨1，aaa", "18", "男");
        String s = data1.toString();
        System.out.println(s.substring(1, s.length() - 1));
    }

    public static byte[] hexColorToBytes(int hexColor) {
        byte[] rgb = new byte[3];
        int red = (hexColor & 0xff0000) >> 16;
        int green = (hexColor & 0x00ff00) >> 8;
        int blue = hexColor & 0x0000ff;
        rgb[0] = (byte) (red);
        rgb[1] = (byte) (green);
        rgb[2] = (byte) (blue);
        return rgb;
    }
}
