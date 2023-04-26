/*
* Copyright 2022 Beijing Zitiao Network Technology Co., Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


@file:Suppress("unused")

package net.bytedance.security.app

import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*
import kotlin.system.exitProcess

const val DEBUG = 0
var INFO = 1
var WARN = 2
var ERROR = 3

/**
 * A simple logger with buffering and  delay writing.
 */
object Log {

    private var curLevel = INFO

    private val fileWriter: FileWriter
    private val buffer: StringBuilder = StringBuilder()
    private var lastTimeWrite: Long = System.currentTimeMillis()
    private const val writeBufferInterval = 1000 //default delay time
    const val TEXT_RESET = "\u001B[0m"
    const val TEXT_BLACK = "\u001B[30m"
    const val TEXT_RED = "\u001B[31m"
    const val TEXT_GREEN = "\u001B[32m"
    const val TEXT_YELLOW = "\u001B[33m"
    const val TEXT_BLUE = "\u001B[34m"
    const val TEXT_PURPLE = "\u001B[35m"
    const val TEXT_CYAN = "\u001B[36m"
    const val TEXT_WHITE = "\u001B[37m"

    init {
        val out = getConfig().outPath
        if (out.endsWith("/out/") || out.endsWith("/out")) {
            println("this message should only appear in test case")
//            Exception().printStackTrace()
        }
        val dirName = "$out/log/"
        val dirFile = File(dirName)
        if (dirFile.exists()) {
            dirFile.delete()
        }
        if (!dirFile.exists()) {
            dirFile.mkdirs()
        }
        val file = File(dirName, "main")
        if (file.exists()) {
            file.delete()
        }
        fileWriter = FileWriter(file, true)
    }

    fun setLevel(level: Int) {
        curLevel = level
    }

    fun getLevelColor(level: Int): String {
        when (level) {
            WARN -> return TEXT_YELLOW
            ERROR -> return TEXT_RED
        }
        return TEXT_RESET
    }

    @Synchronized
    private fun doLog(isLast: Boolean = false) {
        val now = System.currentTimeMillis()
        if (now - lastTimeWrite >= writeBufferInterval || isLast) {
            try {
                fileWriter.write(buffer.toString())
            } catch (e: IOException) {
                e.printStackTrace()
                exitProcess(14)
            }
            buffer.setLength(0)
            lastTimeWrite = now
        }
    }

    private val df = SimpleDateFormat("yyyy-MM-dd HH:mm:ss:S")
    fun logDebug(str: String) {
        if (curLevel <= DEBUG) {
            logStr(str, DEBUG)
        }
    }

    fun logInfo(str: String) {
        if (curLevel <= INFO) {
            logStr(str, INFO)
        }
    }

    fun logWarn(str: String) {
        if (curLevel <= WARN) {
            logStr(str, WARN)
        }
    }

    @Synchronized
    fun logErr(str: String) {
        logStr(str, ERROR)
    }

    //Log and exit
    fun logFatal(str: String) {
        logErr(str)
        flushAndClose()
        exitProcess(-11)
    }

    @Synchronized
    fun flushAndClose() {
        doLog(true)
        fileWriter.flush()
        fileWriter.close()
    }

    fun logStr(str: String, level: Int) {
        val day = Date()
        val time = df.format(day)
        buffer.append(time)
        buffer.append(":")
        buffer.append(str)
        val color = getLevelColor(level)
        if (level < ERROR)
            println("$color$time:$str")
        else
            System.err.println("$color$time:$str")
//        println(buffer.toString())
        buffer.append("\n")
        doLog()
    }


}