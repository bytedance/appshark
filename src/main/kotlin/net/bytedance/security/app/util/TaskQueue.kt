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


package net.bytedance.security.app.util

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import net.bytedance.security.app.Log
import java.util.*
import kotlin.system.exitProcess

/**
 * global hander for oom
 */
val oomHandler = CoroutineExceptionHandler { ctx, exception ->
    if (exception is OutOfMemoryError) {
        val coroutineName = ctx[CoroutineName]?.name
        Log.logErr("${coroutineName} CoroutineException because of oom")
        exitProcess(37)
    }
    if (exception is StackOverflowError) {
        val coroutineName = ctx[CoroutineName]?.name
        Log.logErr("${coroutineName} CoroutineException because of oom")
        exitProcess(38)
    }
    throw exception
}

/**
 * A simple multithreaded task wrapper
 */
class TaskQueue<TaskData>(
    private val name: String,
    private val numberThreads: Int,
    private val action: suspend (TaskData, Int) -> Unit
) {
    private val queue = Channel<TaskData>(numberThreads * 2)

    /**
     * Add a task
     */
    suspend fun addTask(taskData: TaskData, isLast: Boolean = false) {
        queue.send(taskData)
        if (isLast) {
            queue.close()
        }
    }

    /**
     * all tasks are added
     */
    fun addTaskFinished() {
        queue.close()
    }

    /**
     * Be sure to run this function before addTask
     */
    suspend fun runTask(): Job {
        val scope = CoroutineScope(Dispatchers.Default)
        val jobs = ArrayList<Job>()

        for (i in 0 until numberThreads) {
            val job = scope.launch(CoroutineName("$name-$i") + oomHandler) {
                for (taskData in queue) {
                    action(taskData, i)
                }
            }
            jobs.add(job)
        }
        return scope.launch(CoroutineName("$name-joinAll") + oomHandler) { jobs.joinAll() }
    }
}


suspend fun runInMilliSeconds(job: Job, milliSeconds: Long, name: String, timeoutAction: () -> Unit) {
    val start = System.currentTimeMillis()
    val timer = Timer()
    timer.schedule(object : TimerTask() {
        override fun run() {
            runBlocking {
                if (job.isActive) {
                    Log.logWarn("$name runInMilliSeconds timeout")
                    val cancelStart = System.currentTimeMillis()
                    job.cancelAndJoin()
                    val cancelEnd = System.currentTimeMillis()
                    if (cancelEnd - cancelStart > 1000) {
                        Log.logWarn("$name runInMilliSeconds cancelAndJoin takes ${cancelEnd - cancelStart}")
                    }
                    timeoutAction()
                }
            }
        }
    }, milliSeconds)
    job.join()
    timer.cancel()
    val end = System.currentTimeMillis()
    if ((end - start - milliSeconds).toDouble() / milliSeconds > 0.1) {
        Log.logWarn("$name runInMilliSeconds cost more than expected expect=$milliSeconds, actual=${end - start}")
    }
}

