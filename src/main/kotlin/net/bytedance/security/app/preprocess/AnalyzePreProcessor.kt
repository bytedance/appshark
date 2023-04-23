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


package net.bytedance.security.app.preprocess

import kotlinx.coroutines.*
import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.engineconfig.isLibraryClass
import net.bytedance.security.app.util.TaskQueue
import soot.Scene
import soot.SootClass
import soot.SootMethod

/**
create the `Context` for rule processor.
it includes:
- method jimple SSA
- callback patching
- call graph building
 */
class AnalyzePreProcessor(private val parallelCount: Int, val ctx: PreAnalyzeContext) {
    private val methodsVisitor = ArrayList<ArrayList<MethodVisitor>>()
    private val classesVisitor = ArrayList<ClassVisitor>()

    /**
     * You must add all the visitors before calling run
     */
    fun addMethodVisitor(action: () -> MethodVisitor): AnalyzePreProcessor {
        val thisTypeVisitors = ArrayList<MethodVisitor>()
        for (i in 0 until parallelCount) {
            thisTypeVisitors.add(action())
        }
        methodsVisitor.add(thisTypeVisitors)
        return this
    }

    fun addClassVisitor(action: () -> ClassVisitor): AnalyzePreProcessor {
        classesVisitor.add(action())
        return this
    }

    /**
     * process of classes and methods
     */
    suspend fun run() {
        processClasses()
        processMethods()
    }


    @Suppress("ControlFlowWithEmptyBody")
    suspend fun processClasses() {
        val classTasks = TaskQueue<SootClass>("classPreProcessor", parallelCount) { cls, _ ->
            for (classVisitor in classesVisitor) {
                for (m in cls.methods) {
                    // intentionally left blank
                }
                classVisitor.visitClass(cls)
            }
        }
        val task = classTasks.runTask()

        try {
            // Copy it to avoid class changes during traversal
            val classList: List<SootClass> = PLUtils.classes
            for (cls in classList) {
                if (isLibraryClass(cls.name)) {
                    continue
                }
                classTasks.addTask(cls)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }
        classTasks.addTaskFinished()
        task.join()
    }


    private suspend fun processMethods() {
        Log.logInfo("processMethods........")
        val methodTasks =
            TaskQueue<SootMethod>("methodPreProcessor", parallelCount) { method, index ->
//                logDebug("process method ${method.signature}")
                for (methodVisitor in methodsVisitor) {
                    methodVisitor[index].visitMethod(method)
                }
            }

        val task1 = methodTasks.runTask()
        try {
            val classList: List<SootClass> = PLUtils.classes
            for (cls in classList) {
                if (isLibraryClass(cls.name)) {
                    continue
                }
                val methods = ArrayList(cls.methods)
                //may conflict with method resolve
                for (method in methods) {
                    methodTasks.addTask(method)
                }
            }
        } catch (e: Exception) {
//            e.printStackTrace()
            throw e
        }
        methodTasks.addTaskFinished()
        task1.join()
        val scope = CoroutineScope(Dispatchers.Default)
        val jobs = ArrayList<Job>()
        val handler = CoroutineExceptionHandler() { _, exception ->
            exception.printStackTrace()
            Log.logFatal("methodsVisitor collect got $exception")
        }
        for (v in methodsVisitor) {
            val job =
                scope.launch(handler) {
                    v[0].collect(v)
                }
            jobs.add(job)
        }
        jobs.joinAll()
    }

    /**
     * Make sure that this function runs   after `run` and in the main thread,
     * or you may have concurrent data access problems.
     */
    @Synchronized
    fun buildCustomClassCallGraph() {
        val clz = Scene.v().getSootClass(PLUtils.CUSTOM_CLASS)
        for (classVisitor in classesVisitor) {
            classVisitor.visitClass(clz)
        }
        for (methodVisitor in methodsVisitor) {
            for (m in clz.methods) {
                methodVisitor[0].visitMethod(m)
            }
        }
        for (methodVisitor in methodsVisitor) {
            methodVisitor[0].collect(methodVisitor)
        }
    }
}