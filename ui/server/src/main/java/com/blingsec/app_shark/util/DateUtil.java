package com.blingsec.app_shark.util;


import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeConstants;
import org.joda.time.Duration;
import org.joda.time.Interval;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.text.ParseException;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author hu
 * 日期信息处理
 */

@SuppressWarnings("ALL")
@Slf4j
public class DateUtil {
    private DateUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static final String DATE_YEAR_MONTH = "yyyy-MM";
    public static final String DEFAULT_PATTERN = "yyyy-MM-dd";
    public static final String TABLE_DATE_PATTERN = "yyyy_MM_dd";
    public static final String DATE_TIME_PATTERN = "yyyy-MM-dd HH:mm";
    public static final String DATE_MONTH_PATTERN = "yyyy年MM月dd日";
    public static final String DATE_TIME_SECOND_PATTERN = "yyyy-MM-dd HH:mm:ss";
    public static final String DATE_TIME_YND_PATTERN = "yyyy年MM月dd日HH点mm分";
    public static final String DATE_TIME_YNDHMS_PATTERN = "yyyyMMddHHmmss";//秒级别
    public static final String DATE_TIME_YNDHMSS_PATTERN = "yyyyMMddhhmmssSSS";//毫秒级别  12小时制
    public static final String DATE_TIME_YMDHMSS_PATTERN = "yyyyMMddHHmmssSSS";//毫秒24小时制
    public static final String DATE_YND_PATTERN = "yyyyMMdd";
    public static final String DATE_MONTH_POIT_PATTERN = "yyyy.MM.dd";
    public static final String DATE_TIME_SECOND_POINT_PATTERN = "yyyy-MM-dd HH:mm:ss.SSS";
    public static final String DATE_TIME_JOIN_PATTERN = "yyyyMMddHHmm";
    public static final String DATE_MONTH_TIME_PATTERN = "yyyy年M月d日 HH:mm";
    public static final SimpleDateFormat YEAR_MONTH_FORMATTER = new SimpleDateFormat(DATE_YEAR_MONTH);
    public static final DateTimeFormatter SHORT_FORMATTER = DateTimeFormat.forPattern(DEFAULT_PATTERN);
    public static final DateTimeFormatter LONG_FORMATTER = DateTimeFormat.forPattern(DATE_TIME_PATTERN);
    public static final DateTimeFormatter SHORT_CHINA_FORMATTER = DateTimeFormat.forPattern(DATE_MONTH_PATTERN);
    private static final String DATE_MONTH_HOUR_PATTERN = "M月d日HH:mm";
    private static final ThreadLocal<HashMap<String, SimpleDateFormat>> CUSTOMER_MAP_THREAD = new ThreadLocal<>();

    /*
     * 将时间戳转换为指定格式字符串类型时间
     */
    public static String stampToString(String s) {
        String res;
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(DATE_TIME_SECOND_PATTERN);
        long lt = new Long(s);
        Date date = new Date(lt);

        return date2String(date, DATE_TIME_SECOND_PATTERN);
    }

    /**
     * Description: 获取日历对象
     *
     * @return
     * @Version1.0 2015-2-26 下午2:28:35 by 张四有(sy.zhang01@zuche.com)
     */
    public static Calendar getCalendar() {
        return Calendar.getInstance();
    }

    /**
     * Description: 获取当前时间的毫秒
     *
     * @return
     * @Version1.0 2015-2-26 下午2:28:55 by 张四有(sy.zhang01@zuche.com)
     */
    public static long getNowTime() {
        return getCalendar().getTimeInMillis();
    }

    /**
     * Description: 获取当前日期
     *
     * @return
     * @Version1.0 2015-2-26 下午2:30:19 by 张四有(sy.zhang01@zuche.com)
     */
    public static Date getNowDate() {
        return new Date();
    }

    /**
     * Description: 获取给定格式的时间
     *
     * @param pattern
     * @return
     * @Version1.0 2015-2-26 下午2:44:35 by 张四有(sy.zhang01@zuche.com)
     */
    public static String getFormateDate(String pattern) {
        if (StringUtils.isEmpty(pattern)) {
            pattern = DEFAULT_PATTERN;
        }
        SimpleDateFormat sdf = new SimpleDateFormat(pattern);
        return sdf.format(getNowDate());
    }

    /**
     * Description: 获取默认格式的时间
     *
     * @return
     * @Version1.0 2015-2-26 下午2:45:08 by 张四有(sy.zhang01@zuche.com)
     */
    public static String getDefaultFormateDate() {

        return getFormateDate(DEFAULT_PATTERN);
    }

    /**
     * 根据传入字符串 返回yyyy年mm月dd日,月份日期为单位时显示为双位
     */
    public static String getCurrentDateToCNWhole(String dateTime) {

        String year = dateTime.substring(0, 4);
        String month;
        String day;

        month = dateTime.substring(5, 7);
        day = dateTime.substring(8, 10);
        return year + "年" + month + "月" + day + "日";
    }

    /**
     * Description: 将日期字符串转换成日期型
     *
     * @param dateStr
     * @return
     * @Version1.0 2012-11-5 上午08:50:21 by 万久卫（jw.wan@zuche.com）
     */
    public static Date dateString2Date(String dateStr) {
        return dateString2Date(dateStr, DEFAULT_PATTERN);
    }

    public static Date dateString2DateByPattern(String dateStr, String pattern) {
        if (StringUtils.isEmpty(pattern)) {
            pattern = DATE_TIME_PATTERN;
        }
        return dateString2Date(dateStr, pattern);
    }

    /**
     * Description: 将日期字符串转换成指定格式日期
     *
     * @param dateStr
     * @param partner
     * @return
     * @Version1.0 2012-11-5 上午08:50:55 by springMT
     */
    public static Date dateString2Date(String dateStr, String partner) {
        Date returnDate = null;
        try {
            if (StringUtils.isNotEmpty(dateStr) && StringUtils.isNotEmpty(partner)) {
                SimpleDateFormat formatter = getSimpleDateFormat(partner);
                ParsePosition pos = new ParsePosition(0);
                returnDate = formatter.parse(dateStr, pos);
            }
        } catch (NullPointerException e) {
            return null;
        }
        return returnDate;
    }

    /**
     * 获取指定日期的年份
     *
     * @param p_date util.Date日期
     * @return int 年份
     */
    public static int getYearOfDate(Date p_date) {
        Calendar c = Calendar.getInstance();
        c.setTime(p_date);
        return c.get(Calendar.YEAR);
    }

    /**
     * Description: 获取日期字符串的年份
     *
     * @param p_date 字符串日期
     * @return int 年份
     * @Version1.0 2012-11-5 上午08:51:51 by 万久卫（jw.wan@zuche.com）
     */
    public static int getYearOfDate(String p_date) {
        return getYearOfDate(dateString2Date(p_date));
    }

    /**
     * Description: 获取指定日期的月份
     *
     * @param p_date java.util.Date
     * @return int 月份
     * @Version1.0 2012-11-5 上午08:52:14 by 万久卫（jw.wan@zuche.com）
     */
    public static int getMonthOfDate(Date p_date) {
        Calendar c = Calendar.getInstance();
        c.setTime(p_date);
        return c.get(Calendar.MONTH) + 1;
    }

    /**
     * Description: 获取日期字符串的月份
     *
     * @param date 字符串日期
     * @return int 月份
     * @Version1.0 2012-11-5 上午08:53:22 by 万久卫（jw.wan@zuche.com）
     */
    public static int getMonthOfDate(String date) {
        return getMonthOfDate(dateString2Date(date));
    }

    /**
     * 获取指定日期的日份
     *
     * @param p_date util.Date日期
     * @return int 日份
     */
    public static int getDayOfDate(Date p_date) {
        Calendar c = Calendar.getInstance();
        c.setTime(p_date);
        return c.get(Calendar.DAY_OF_MONTH);
    }

    /**
     * 获取指定日期的周 与 Date .getDay()兼容
     *
     * @param date String 日期
     * @return int 周
     */
    public static int getWeekOfDate(String date) {
        Date p_date = dateString2Date(date);
        return getWeekOfDate(p_date);
    }

    /**
     * 获取指定日期的周 与 Date .getDay()兼容
     *
     * @param date util.Date日期
     * @return int 周
     */
    public static int getWeekOfDate(Date date) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        return c.get(Calendar.DAY_OF_WEEK) - 1;
    }

    /**
     * 获取指定日期的小时
     *
     * @param p_date util.Date日期
     * @return int 日份
     */
    public static int getHourOfDate(Date p_date) {
        Calendar c = Calendar.getInstance();
        c.setTime(p_date);
        return c.get(Calendar.HOUR_OF_DAY);
    }

    /**
     * 获取指定日期的分钟
     *
     * @param p_date util.Date日期
     * @return int 分钟
     */
    public static int getMinuteOfDate(Date p_date) {
        Calendar c = Calendar.getInstance();
        c.setTime(p_date);
        return c.get(Calendar.MINUTE);
    }

    /**
     * Description: 日期转化指定格式的字符串型日期
     *
     * @param p_utilDate java.util.Date
     * @param p_format   日期格式
     * @return 字符串格式日期
     * @Version1.0 2012-11-5 上午08:58:44 by 万久卫（jw.wan@zuche.com）
     */
    public static String date2String(
            Date p_utilDate, String p_format) {
        String l_result = "";
        if (p_utilDate != null) {
            SimpleDateFormat sdf = getSimpleDateFormat(p_format);
            l_result = sdf.format(p_utilDate);
        }
        return l_result;
    }

    /**
     * Description: 日期转化指定格式的字符串型日期
     *
     * @param p_utilDate java.util.Date
     * @return 字符串格式日期
     * @Version1.0 2012-11-5 上午08:58:58 by 万久卫（jw.wan@zuche.com）
     */
    public static String date2String(
            Date p_utilDate) {
        return date2String(p_utilDate, DEFAULT_PATTERN);
    }


    /**
     * Description: 时间计算(根据时间推算另个日期)
     *
     * @param date  日期
     * @param type  类型 y,M,d,h,m,s 年、月、日、时、分、秒
     * @param value 添加值
     * @return
     * @Version1.0 2012-4-12 下午12:59:39 by 王星皓（albertwxh@gmail.com）创建
     */
    public static Date dateAdd(Date date, String type, int value) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        if (type.toLowerCase().equals("y") || type.toLowerCase().equals("year"))
            c.add(Calendar.YEAR, value);
        else if (type.equals("M") || type.toLowerCase().equals("month"))
            c.add(Calendar.MONTH, value);
        else if (type.toLowerCase().equals("d") || type.toLowerCase().equals("date"))
            c.add(Calendar.DATE, value);
        else if (type.toLowerCase().equals("h") || type.toLowerCase().equals("hour"))
            c.add(Calendar.HOUR, value);
        else if (type.equals("m") || type.toLowerCase().equals("minute"))
            c.add(Calendar.MINUTE, value);
        else if (type.toLowerCase().equals("s") || type.toLowerCase().equals("second"))
            c.add(Calendar.SECOND, value);
        return c.getTime();
    }

    /**
     * Description:
     *
     * @param date
     * @param type
     * @param value
     * @return
     * @Version1.0 2012-11-5 上午09:39:21 by 万久卫（jw.wan@zuche.com）
     */
    public static Date dateAdd2Date(Date date, String type, int value) {
        return dateAdd(date, type, value);
    }

    /**
     * Description:
     *
     * @param dateStr
     * @param type
     * @param value
     * @param pattern
     * @return
     * @Version1.0 2012-11-5 上午09:18:13 by 万久卫（jw.wan@zuche.com）
     */
    public static Date dateAdd2Date(String dateStr, String type, int value, String pattern) {
        Date date = DateUtil.dateString2Date(dateStr, pattern);
        return dateAdd(date, type, value);

    }

    /**
     * Description:
     *
     * @param dateStr
     * @param type
     * @param value
     * @return
     * @Version1.0 2012-11-5 上午09:19:59 by 万久卫（jw.wan@zuche.com）
     */
    public static Date dateAdd2Date(String dateStr, String type, int value) {
        Date date = DateUtil.dateString2Date(dateStr, DateUtil.DEFAULT_PATTERN);
        return dateAdd(date, type, value);

    }

    /**
     * Description:
     *
     * @param date
     * @param type
     * @param value
     * @return
     * @Version1.0 2012-11-5 上午09:43:47 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2String(Date date, String type, int value) {
        Date dateD = dateAdd2Date(date, type, value);
        return date2String(dateD);
    }

    /**
     * Description:
     *
     * @param date
     * @param type
     * @param value
     * @param pattern
     * @return
     * @Version1.0 2012-11-5 上午10:01:50 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2String(Date date, String type, int value, String pattern) {
        Date dateD = dateAdd2Date(date, type, value);
        return date2String(dateD, pattern);
    }

    /**
     * Description:
     *
     * @param dateStr
     * @param type
     * @param value
     * @param pattern
     * @return
     * @Version1.0 2012-11-5 上午09:43:24 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2String(String dateStr, String type, int value, String pattern) {
        Date date = dateAdd2Date(dateStr, type, value, pattern);
        return date2String(date);
    }

    /**
     * Description:
     *
     * @param dateStr
     * @param type
     * @param value
     * @return
     * @Version1.0 2012-11-5 上午09:42:12 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2String(String dateStr, String type, int value) {
        Date date = dateAdd2Date(dateStr, type, value);
        return date2String(date);
    }

    public static String dateAdd2String(String dateStr, int value) {
        return dateAdd2String(dateStr, "d", value);
    }

    /**
     * Description:
     *
     * @param dateStr
     * @param isAddDay
     * @return
     * @Version1.0 2012-11-5 上午10:19:24 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2String(String dateStr, boolean isAddDay) {
        String returndateStr = dateStr;
        try {
            if (isAddDay) {
                dateStr = dateAdd2String(dateStr, "d", 1);
            }
            Date date = dateString2Date(dateStr);
            int month = getMonthOfDate(date);
            int day = getDayOfDate(date);
            returndateStr = month + "." + day;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        return returndateStr;
    }

    /**
     * Description:
     *
     * @param dateStr
     * @return
     * @Version1.0 2012-11-5 上午10:23:46 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2String(String dateStr) {
        return dateAdd2String(dateStr, false);
    }

    /**
     * Description:
     *
     * @param dateStr
     * @param type
     * @param value
     * @param pattern
     * @return
     * @Version1.0 2012-11-5 上午09:43:24 by 万久卫（jw.wan@zuche.com）
     */
    public static String dateAdd2PatternString(String dateStr, String type, int value, String pattern) {
        Date date = dateAdd2Date(dateStr, type, value, pattern);
        return date2String(date, pattern);
    }

    /**
     * @param @param  p_date
     * @param @return
     * @return boolean
     * @throws
     * @Title: checkWeekendDay
     * @Description: 判断是平时还是周末
     */

    public static boolean checkWeekendDay(String p_date) {
        Calendar c = Calendar.getInstance();
        c.setTime(dateString2Date(p_date));
        int num = c.get(Calendar.DAY_OF_WEEK);

        //如果为周六 周日则为周末  1星期天 2为星期六
        return num == 6 || num == 7 || num == 1;
    }

    /**
     * @param @param  startTime
     * @param @param  endTime
     * @param @return
     * @param @throws ParseException
     * @return String[][]
     * @throws
     * @Title: getMonthsByTime
     * @Description: 按时间段计算月份跨度  计算出所包含的月份
     */
    @SuppressWarnings("static-access")
    public static int[][] getMonthsByTime(String startTime, String endTime) {
        Date st;
        Date et;

        try {
            et = getSimpleDateFormat(DEFAULT_PATTERN).parse(endTime);
            st = getSimpleDateFormat(DEFAULT_PATTERN).parse(startTime);
        } catch (ParseException e) {
            return null;
        }


        Calendar ca1 = Calendar.getInstance();
        Calendar ca2 = Calendar.getInstance();
        ca1.setTime(st);
        ca2.setTime(et);

        int ca1Year = ca1.get(Calendar.YEAR);
        int ca1Month = ca1.get(Calendar.MONTH);

        int ca2Year = ca2.get(Calendar.YEAR);
        int ca2Month = ca2.get(Calendar.MONTH);
        int countMonth;//这个是用来计算得到有多少个月时间的一个整数,
        if (ca1Year == ca2Year) {
            countMonth = ca2Month - ca1Month;
        } else {
            countMonth = (ca2Year - ca1Year) * 12 + (ca2Month - ca1Month);
        }

        int months[][] = new int[countMonth + 1][2];        //年月日二维数组

        for (int i = 0; i < countMonth + 1; i++) {
            //每次在原基础上累加一个月

            months[i][0] = ca1.get(Calendar.YEAR);
            months[i][1] = ca1.get(Calendar.MONTH);
            months[i][1] += 1;
            ca1.add(ca1.MONTH, 1);
        }

        return months;
    }

    /**
     * yyyy-MM-dd HH:mm 格式日期 转化 为 M月d日HH:mm 格式日期
     *
     * @param date String
     * @return String
     */
    public static String string2String(String date) throws ParseException {
        return date2String(dateString2Date(date, DATE_TIME_PATTERN), DATE_MONTH_HOUR_PATTERN);
    }

    /**
     * Description:
     *
     * @param date
     * @param pattern
     * @return
     * @throws ParseException
     * @Version1.0 2012-11-9 上午10:57:30 by 万久卫（jw.wan@zuche.com）
     */
    public static String string2String(String date, String pattern) throws ParseException {
        return date2String(dateString2Date(date), pattern);
    }

    public static String string2StringByPattern(String date, String pattern) throws ParseException {
        return date2String(dateString2DateByPattern(date, DATE_TIME_PATTERN), pattern);
    }

    /**
     * Description: 得到两个时间差分钟
     *
     * @param startTime 开始时间
     * @param toTime    结束时间
     * @param pattern   日期格式字符串
     * @return long 时间差分钟
     * @Version1.0 2012-11-5 上午09:04:45 by 万久卫（jw.wan@zuche.com）
     */
    public static long getDateDiff(String startTime, String toTime, String pattern) {
        long diff = getDateDiffLong(startTime, toTime, pattern);
        diff = diff / 1000 / 60;
        return diff;
    }

    /**
     * Description: 得到两个时间差的天数
     *
     * @param startTime 开始时间
     * @param toTime    结束时间
     * @param pattern   日期格式字符串
     * @return int 时间差天数
     * @Version1.0 2015-5-27 上午9:08:31 by 张四有(sy.zhang01@zuche.com)
     */
    public static int getDayDiff(String startTime, String toTime, String pattern) {
        long diff = getDateDiff(startTime, toTime, pattern);
        int day = (int) (diff / (60 * 24));
        return day;
    }

    /**
     * Description:
     *
     * @param startTime
     * @param toTime
     * @param pattern
     * @return
     * @Version1.0 2012-11-9 上午10:25:23 by 万久卫（jw.wan@zuche.com）
     */
    public static long getDateDiffLong(String startTime, String toTime, String pattern) {
        long diff = 0L;
        if (StringUtils.isNotBlank(startTime) && StringUtils.isNotBlank(toTime)) {
            SimpleDateFormat format = getSimpleDateFormat(pattern);
            ParsePosition pos = new ParsePosition(0);
            Date startTimeD = format.parse(startTime, pos);
            pos.setIndex(0);
            Date toTimeD = format.parse(toTime, pos);
            if (startTimeD != null && toTimeD != null) {
                diff = startTimeD.getTime() - toTimeD.getTime();
            }
        }
        return diff;
    }

    /**
     * Description: 得到两个时间差
     *
     * @param startTime 开始时间
     * @param toTime    结束时间
     * @return long 时间差
     * @Version1.0 2012-11-5 上午09:05:27 by 万久卫（jw.wan@zuche.com）
     */
    public static long getDateDiff(String startTime, String toTime) {
        return getDateDiff(startTime, toTime, DATE_TIME_PATTERN);
    }

    /**
     * Description: 得到两个时间差
     *
     * @param startTimeD 开始时间
     * @param toTime     结束时间
     * @param pattern    日期格式字符串
     * @return long 时间差
     * @Version1.0 2012-11-5 上午09:09:34 by 万久卫（jw.wan@zuche.com）
     */
    public static long getDateDiff(Date startTimeD, String toTime, String pattern) {
        long diff = 0;
        Date toTimeD = dateString2Date(toTime, pattern);
        if (Objects.nonNull(toTimeD)) {
            diff = startTimeD.getTime() - toTimeD.getTime();
        }
        return diff;
    }

    /**
     * Description:
     *
     * @param hour
     * @param minute
     * @return
     * @Version1.0 2012-11-5 上午10:26:46 by 万久卫（jw.wan@zuche.com）
     */
    public static Integer getMinuteTotal(String hour, String minute) {
        return getMinuteTotal(Integer.parseInt(hour), Integer.parseInt(minute));
    }

    /**
     * Description:
     *
     * @param hour
     * @param minute
     * @return
     * @Version1.0 2012-11-5 上午10:26:50 by 万久卫（jw.wan@zuche.com）
     */
    public static Integer getMinuteTotal(Integer hour, Integer minute) {
        return hour * 60 + minute;
    }

    /**
     * Description:
     *
     * @param leaseTime
     * @param leaseDays
     * @return
     * @Version1.0 2012-11-5 上午10:27:25 by 万久卫（jw.wan@zuche.com）
     */
    public static String[] getallyearMonth(Date leaseTime, int leaseDays) {
        List<String> yearList = new ArrayList<String>();
        List<String> monthList = new ArrayList<String>();
        String yearString;
        String monthString;
        StringBuilder dateString = new StringBuilder();
        StringBuilder sBuffer = new StringBuilder();
        String[] returnResult = new String[3];
        for (int i = 0; i < leaseDays; i++) {
            String correctDate = DateUtil.dateAdd2String(leaseTime, "d", i);
            String year = correctDate.split("-")[0];
            String month = correctDate.split("-")[1];
            if (!yearList.contains(year))
                yearList.add(year);
            if (!monthList.contains(month))
                monthList.add(month);
            if (i == leaseDays - 1)
                dateString.append(correctDate);
            else
                dateString.append(correctDate).append(",");

        }
        for (String month : monthList) {
            sBuffer.append(month).append(",");
        }
        monthString = sBuffer.toString();
        sBuffer.delete(0, sBuffer.length());
        for (String year : yearList) {
            sBuffer.append(year).append(",");
        }
        yearString = sBuffer.toString();
        if (monthString.lastIndexOf(",") == monthString.length() - 1)
            monthString = monthString.substring(0, monthString.length() - 1);
        if (yearString.lastIndexOf(",") == yearString.length() - 1)
            yearString = yearString.substring(0, yearString.length() - 1);
        returnResult[0] = yearString;
        returnResult[1] = monthString;
        returnResult[2] = dateString.toString();
        return returnResult;
    }

    private static SimpleDateFormat getSimpleDateFormat(String pattern) {
        SimpleDateFormat simpleDateFormat;
        HashMap<String, SimpleDateFormat> simpleDateFormatMap = CUSTOMER_MAP_THREAD.get();
        if (simpleDateFormatMap != null && simpleDateFormatMap.containsKey(pattern)) {
            simpleDateFormat = simpleDateFormatMap.get(pattern);
        } else {
            simpleDateFormat = new SimpleDateFormat(pattern);
            if (simpleDateFormatMap == null) {
                simpleDateFormatMap = new HashMap<String, SimpleDateFormat>();
            }
            simpleDateFormatMap.put(pattern, simpleDateFormat);
            CUSTOMER_MAP_THREAD.set(simpleDateFormatMap);
        }

        return simpleDateFormat;
    }

    private void unload() {
        CUSTOMER_MAP_THREAD.remove();
    }

    public static List<String> getRightYearMonth(String[] year, String[] month, String fromDate, String toDate) {
        List<String> dayArray = getRightDay(year, month, fromDate, toDate);
        if (dayArray != null && dayArray.size() > 0) {
            for (int i = 0, len = dayArray.size(); i < len; i++) {
                dayArray.set(i, dayArray.get(i).substring(0, 7));
            }
        }
        return dayArray;
    }

    private static List<String> getRightDay(String[] years, String[] months, String fromDate, String toDate) {
        DateTime from = new DateTime(Integer.parseInt(fromDate.substring(0, 4)), Integer.parseInt(fromDate.substring
                (5, 7)), 1, 0, 0);
        DateTime to = new DateTime(Integer.parseInt(toDate.substring(0, 4)), Integer.parseInt(toDate.substring(5,
                7)), 2, 0, 0);
        Interval interval = new Interval(from, to);
        List<String> list = Lists.newArrayList();
        DateTime tmp;
        for (String year : years) {
            for (String month : months) {
                tmp = new DateTime(Integer.parseInt(year), Integer.parseInt(month), 1, 0, 0);
                if (interval.contains(tmp)) {
                    list.add(SHORT_FORMATTER.print(tmp));
                }
            }
        }

        return list;
    }

    public static Integer getTermMaxLeng(String[] year, String[] month, String fromDate, String toDate) {
        List<String> dayArray = getRightDay(year, month, fromDate, toDate);
        Integer size = 0;
        if (dayArray != null) {
            size = dayArray.size();
        }
        return size;
    }

    /**
     * 获得指定日期及指定天数之内的所有日期列表
     *
     * @param pDate 指定日期 格式:yyyy-MM-dd
     * @param count 取指定日期后的count天
     * @return
     * @throws ParseException
     */
    public static Vector<String> getDatePeriodDay(String pDate, int count)
            throws ParseException {
        Vector<String> v = new Vector<String>();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(DateUtil.dateString2Date(pDate));
        v.add(DateUtil.date2String(calendar.getTime()));

        for (int i = 0; i < count - 1; i++) {
            calendar.add(Calendar.DATE, 1);
            v.add(DateUtil.date2String(calendar.getTime()));
        }

        return v;
    }

    /**
     * 获得指定日期内的所有日期列表
     *
     * @param sDate 指定开始日期 格式:yyyy-MM-dd
     * @param sDate 指定开始日期 格式:yyyy-MM-dd
     * @return String[]
     * @throws ParseException
     */
    public static String[] getDatePeriodDay(String sDate, String eDate)
            throws ParseException {
        if (dateCompare(sDate, eDate)) {
            return null;
        }
        Calendar calendar = Calendar.getInstance();
        Calendar calendar_ = Calendar.getInstance();
        calendar.setTime(DateUtil.dateString2Date(sDate));
        long l1 = calendar.getTimeInMillis();
        calendar_.setTime(DateUtil.dateString2Date(eDate));
        long l2 = calendar_.getTimeInMillis();
        // 计算天数
        long days = (l2 - l1) / (24 * 60 * 60 * 1000) + 1;

        String[] dates = new String[(int) days];
        dates[0] = (DateUtil.date2String(calendar.getTime()));
        for (int i = 1; i < days; i++) {
            calendar.add(Calendar.DATE, 1);
            dates[i] = (DateUtil.date2String(calendar.getTime()));
        }
        return dates;
    }

    /**
     * @param startTime 开始日期
     * @param endTime   结束日期
     * @param pattern   日期格式
     * @return
     */
    public static List<String> getDays(String startTime, String endTime) {
        // 返回的日期集合
        List<String> days = new ArrayList<String>();
        SimpleDateFormat dateFormat = new SimpleDateFormat(DEFAULT_PATTERN);
        try {
            Date start = dateFormat.parse(startTime);
            Date end = dateFormat.parse(endTime);

            Calendar tempStart = Calendar.getInstance();
            tempStart.setTime(start);

            Calendar tempEnd = Calendar.getInstance();
            tempEnd.setTime(end);
            tempEnd.add(Calendar.DATE, +1);// 日期加1(包含结束)
            while (tempStart.before(tempEnd)) {
                days.add(dateFormat.format(tempStart.getTime()));
                tempStart.add(Calendar.DAY_OF_YEAR, 1);
            }
        } catch (ParseException e) {
            log.error(e.getMessage(), e);
        }
        return days;
    }

    public static List<String> getDatePeriodDayList(String sDate, String eDate) {
        List<String> list = null;
        try {
            String[] dateArray = getDatePeriodDay(sDate, eDate);
            if (dateArray != null && dateArray.length > 0) {
                list = new ArrayList<String>();
                for (String date : dateArray) {
                    list.add(date);
                }
            }
        } catch (Exception e) {

        }
        return list;
    }

    /**
     * 比较日期大小
     *
     * @param compareDate
     * @param toCompareDate
     * @return
     */

    public static boolean dateCompare(String compareDate, String toCompareDate) {
        boolean comResult = false;
        Date comDate = DateUtil.dateString2Date(compareDate);
        Date toComDate = DateUtil.dateString2Date(toCompareDate);
        if (Objects.isNull(toComDate)) {
            return comResult;
        }
        if (Objects.isNull(comDate)) {
            return comResult;
        }
        if (comDate.after(toComDate)) {
            comResult = true;
        }
        return comResult;
    }

    /**
     * Description: 判断字符串是否日期格式(yyyy-MM-dd 或者 yyyy-MM-dd HH:mm)
     *
     * @param time
     * @return
     * @Version1.0 2013-1-5 下午01:47:09 by 万久卫（jw.wan@zuche.com）
     */
    public static boolean isDateFormat(String time) {
        boolean isDate = true;
        if (StringUtils.isNotBlank(time)) {
            SimpleDateFormat format = getSimpleDateFormat(DEFAULT_PATTERN);
            ParsePosition pos = new ParsePosition(0);
            Date timeD = format.parse(time, pos);
            if (timeD == null) {
                format = getSimpleDateFormat(DATE_TIME_PATTERN);
                pos.setIndex(0);
                timeD = format.parse(time, pos);
                if (timeD == null) {
                    isDate = false;
                }
            }

        }
        return isDate;
    }

    public static Duration getDuration(String fromTime, String toTime, String pattern) {

        return getDuration(fromTime, toTime, DateTimeFormat.forPattern(pattern));
    }

    public static Duration getDuration(String fromTime, String toTime, DateTimeFormatter formatter) {
        Duration duration = null;
        if (StringUtils.isNotBlank(fromTime) && StringUtils.isNotBlank(toTime)) {
            final DateTime fromDateTime = formatter.parseDateTime(fromTime);
            final DateTime toDateTime = formatter.parseDateTime(toTime);
            duration = new Duration(fromDateTime, toDateTime);
        }
        return duration;
    }

    public static Duration getDuration(String fromTime, String toTime) {
        return getDuration(fromTime, toTime, SHORT_FORMATTER);
    }

    public static String getMaxDateByMonth(Date currentDate) {
        return getMaxDateByMonth(date2String(currentDate));
    }

    public static String getMinDateByMonth(Date currentDate) {
        return getMinDateByMonth(date2String(currentDate));
    }

    public static String getMaxDateByMonth(String currentDate) {
        Date sDate1 = DateUtil.dateString2Date(currentDate);
        Calendar cDay1 = Calendar.getInstance();
        cDay1.setTime(sDate1);
        final int lastDay = cDay1.getActualMaximum(Calendar.DAY_OF_MONTH);
        return currentDate.substring(0, 8) + lastDay;
    }

    public static String getMinDateByMonth(String currentDate) {
        return currentDate.substring(0, 8) + "01";
    }

    /**
     * Description: 获取租期
     *
     * @param fromTime
     * @param toTime
     * @param isOverHourBuf
     * @return
     * @Version1.0 2015-6-17 下午2:18:20 by 张四有(sy.zhang01@zuche.com)
     */
    public static Integer getRentDay(String fromTime, String toTime, StringBuilder isOverHourBuf) {
        String rentDay = null;
        final Duration duration = getDuration(modifyDateTimeStr(fromTime), modifyDateTimeStr(toTime), DateUtil.LONG_FORMATTER);
        if (duration != null) {
            long days = duration.getStandardDays();
            long minutes = duration.getStandardMinutes() % DateTimeConstants.MINUTES_PER_DAY;
            if (days == 0) {
                rentDay = "1";
            } else {

                if (minutes > 240) {
                    days += 1;
                } else if (minutes > 0 && isOverHourBuf != null) {
                    isOverHourBuf.append("1");
                }
                rentDay = String.valueOf(days);

            }

        }
        return rentDay == null ? -9999 : Integer.parseInt(rentDay);
    }

    public static String modifyDateTimeStr(String str) {
        if (str != null && str.length() == 10) {
            return str + " 00:00";
        } else {
            return str;
        }
    }

    /**
     * Description: 在跟定的日期格式下，比较日期dateTime是否在holidayStart 和 holidayEnd之间
     *
     * @param holidayStart
     * @param holidayEnd
     * @param dateTime
     * @param patternStr
     * @return
     * @Version1.0 2015-11-10 上午10:03:48 by 张四有(sy.zhang01@zuche.com)
     */
    public static boolean isBetweenDateTime(String holidayStart, String holidayEnd, String dateTime, String patternStr) {
        boolean flag = false;
        if (StringUtils.isNotEmpty(holidayStart) && StringUtils.isNotEmpty(holidayEnd)) {
            if (StringUtils.isEmpty(patternStr)) { //日历格式为空时，获取默认格式
                patternStr = DateUtil.DEFAULT_PATTERN;
            }
            if (StringUtils.isEmpty(dateTime)) { //比较时间为空时，获取给定格式的当前时间
                dateTime = getFormateDate(patternStr);
            }
            if (DateUtil.getDateDiff(dateTime, holidayStart, patternStr) >= 0 && DateUtil.getDateDiff(dateTime, holidayEnd, patternStr) <= 0) { //9月份
                flag = true;
            }
        }
        return flag;
    }

    /**
     * Description: 时间区间判断
     *
     * @param strDate   "2016-04-15";
     * @param startDate "2016-04-15";
     * @param endDate   "2016-04-15";
     * @return
     * @Version1.0 2016-4-13 上午10:18:18 by 徐良 xuliang04@zuche.com
     */
    public static boolean betweenTimeInterval(String strDate,
                                              String startDate, String endDate) {
        boolean result = false;
        if (StringUtils.isNotEmpty(strDate)
                && StringUtils.isNotEmpty(startDate)
                && StringUtils.isNotEmpty(endDate)
                && DateUtil.getDateDiff(strDate, startDate,
                DateUtil.DEFAULT_PATTERN) >= 0
                && DateUtil.getDateDiff(endDate, strDate,
                DateUtil.DEFAULT_PATTERN) >= 0) {
            result = true;
        }
        return result;
    }

    /**
     * 获取两个日期之间的所有日期
     *
     * @param startDate
     * @param endDate
     * @return
     */
    public static List<String> splitDateList(Date startDate, Date endDate) {
        List<String> listDate = new ArrayList<>();
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(startDate);
            while (calendar.getTime().before(endDate) || calendar.getTime().equals(endDate)) {
                listDate.add(YEAR_MONTH_FORMATTER.format(calendar.getTime()));
                calendar.add(Calendar.MONTH, 1);
            }
            return listDate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return listDate;
    }

    /**
     * 毫秒差计算相差
     * two-one
     * 相差几秒几毫秒
     */
    public static String getDistanceTime(Long diff) {
        long day = 0;//天数差
        long hour = 0;//小时数差
        long min = 0;//分钟数差
        long second = 0;//秒数差
        StringBuffer result = new StringBuffer();
        day = diff / (24 * 60 * 60 * 1000);
        hour = (diff / (60 * 60 * 1000) - day * 24);
        min = ((diff / (60 * 1000)) - day * 24 * 60 - hour * 60);
        second = (diff / 1000) - day * 24 * 60 * 60 - hour * 60 * 60 - min * 60;
        String daystr = day + "天";
        String hourStr = hour + "小时";
        String minStr = min + "分";
        String secondStr = second + "秒";
        if (day != 0) {
            result.append(daystr);
        }
        if (hour != 0) {
            result.append(hourStr);
        }
        if (min != 0) {
            result.append(minStr);
        }
        if (second != 0) {
            result.append(secondStr);
        }
        return result.toString();
    }
}
