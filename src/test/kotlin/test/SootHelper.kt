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


package test

import net.bytedance.security.app.PLUtils
import org.junit.jupiter.api.Assertions
import soot.Scene
import soot.options.Options
import java.io.File
import java.io.InputStream
import java.util.concurrent.TimeUnit


object SootHelper {

    @Synchronized
    fun createClassFile(paths: List<String>, target: String) {
        val f = File(target)
        if (f.exists()) {
            return
        }
        runCommand("mkdir -p $target")

        var javas = ""
        paths.forEach {
            val f2 = File(it)
            if (!f2.exists()) {
                throw Exception("$it not exist")
            }
            javas += " $it/*.java "
        }
        val path = System.getProperty("user.dir")
        println("Working Directory = $path")
        runCommand("javac $javas -d $target")
    }

    fun runCommand(cmd: String) {
        println("run command: $cmd")
        val result = exec(cmd, 60)
        println("$result")
    }

    fun exec(cmd: String?, timeOut: Int): String? {
        val args = arrayOf("/bin/sh", "-c", cmd)
        val p = Runtime.getRuntime().exec(args)
        val res = p.waitFor(timeOut.toLong(), TimeUnit.SECONDS)
        if (!res) {
            return "Time out"
        }
        val inputStream: InputStream = p.inputStream
        var result = ""
        var data = inputStream.readBytes()
        result += String(data)
//        if (result === "") {
        data = p.errorStream.readBytes()
        result += String(data)
//        }
        return result
    }


    @Synchronized
    fun initSoot(name: String, paths: List<String>) {
        //1. compile java to class
        val target = "/tmp/appshark/$name"
        createClassFile(paths, target)
        initSootForClasses(name, target)
    }


    fun initSootForClasses(_name: String, classesFilePath: String) {
        val version = System.getProperty("java.version")
        Assertions.assertTrue(version.startsWith("11."), "this test only works on jdk11")
        soot.G.reset()
        TestHelper.appsharkInit()
        Options.v().set_src_prec(Options.src_prec_class)
        Options.v().set_process_dir(listOf(classesFilePath))
        Options.v().set_debug(true)
        Options.v().set_verbose(true)
        Options.v().set_validate(false)
        Options.v().set_whole_program(true)
        Options.v().set_allow_phantom_refs(true)
        Options.v().set_output_format(Options.output_format_jimple)
        Options.v().set_keep_line_number(true)
        //exclude
        Options.v().set_exclude(listOf("java.*", "org.*", "sun.*", "android.*"))
        Options.v().set_no_bodies_for_excluded(true)
        Scene.v().loadNecessaryClasses()
        PLUtils.updateSootClasses()
    }
}