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
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong

internal class TaskQueueTest {

    @Test
    fun runTask() {
//        val indexSum = Concurrent()
        val valSum = AtomicLong()
        val q = TaskQueue<Long>("test", 7) { task, _ ->
            delay(100)
            valSum.addAndGet(task)
//            println("process $task,$index")
        }
        runBlocking {
            val job = q.runTask()
            var sum = 0
            for (i in 1 until 1000) {
                sum += i
                q.addTask(i.toLong())
            }
            q.addTaskFinished()
            job.join()
            Assertions.assertEquals(sum.toLong(), valSum.get())
        }

    }

    suspend fun throwOutOfMemoryError() {
        throw OutOfMemoryError()
    }

//    @Test
//    fun runOutOfMemory() {
//        val q = TaskQueue<Long>("test", 7) { task, _ ->
//            delay(100)
//            throwOutOfMemoryError()
////            println("process $task,$index")
//        }
//        runBlocking {
//            val job = q.runTask()
//            var sum = 0
//            for (i in 1 until 1000) {
//                sum += i
//                q.addTask(i.toLong())
//            }
//            q.addTaskFinished()
//            job.join()
//        }
//    }

    @Test
    fun testCancel() {
        runBlocking {
            val startTime = System.currentTimeMillis()
            val job = launch(Dispatchers.Default) {
                var nextPrintTime = startTime
                var i = 0
                while (i < 5) { // computation loop, just wastes CPU
                    // print a message twice a second
                    if (System.currentTimeMillis() >= nextPrintTime) {
                        println("job: I'm sleeping ${i++} ...")
                        nextPrintTime += 500L
                    }
                    yield()
                }
            }
            delay(1300L) // delay a bit
            println("main: I'm tired of waiting!")
            job.cancelAndJoin() // cancels the job and waits for its completion
            println("main: Now I can quit.")
        }
    }

    @Test
    fun testRunInMilliSeconds() {
        runBlocking {
            val job1 = launch(Dispatchers.Default) {
                delay(1000)
                println("job1 finished after delay")
            }
            val start = System.currentTimeMillis()
            var reasonTimeout = false
            runInMilliSeconds(job1, 3000, "testRunInMilliSeconds") {
                println("finished because of timeout")
                reasonTimeout = true
            }
            Assertions.assertTrue(System.currentTimeMillis() - start > 1000)
//            Assertions.assertTrue(System.currentTimeMillis() - start < 2000)
            println("runInMilliSeconds finished")
            delay(4000)
            Assertions.assertFalse(reasonTimeout)
        }
    }
}