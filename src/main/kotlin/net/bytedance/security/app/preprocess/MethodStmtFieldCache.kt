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

import soot.RefType
import soot.SootField
import soot.SootMethod
import soot.jimple.Stmt

class CallSite(val method: SootMethod, val stmt: Stmt) {
    /**
     * r1="aaa"
     * r1=o.f("a1","a2,"a3")
     * Extract a constant string from stmt above
     */
    fun constString(): List<String> {
        return MethodFieldConstCacheVisitor.getConstStringFromStmt(stmt)
    }

    override fun toString(): String {
        return "CallSite(method=$method, stmt=$stmt)"
    }
}

class MethodStmtFieldCache {

    /**
     * key is the callee function,value is the caller and it's callsite
     * Direct is a function called directly, regardless of the CHA relationship
     */
    val methodDirectRefs: MutableMap<SootMethod, MutableSet<CallSite>> = HashMap()
    val methodHeirRefs: MutableMap<SootMethod, MutableSet<CallSite>> = HashMap()

    /**
     * key is the field to load,value are callsites
     *  a=b.c;
     */
    val loadFieldRefs: MutableMap<SootField, MutableSet<CallSite>> = HashMap()

    /**
     * key is the field to store,value are callsites
     *  b.c=a;
     */
    val storeFieldRefs: MutableMap<SootField, MutableSet<CallSite>> = HashMap()

    /**

    key if const string pattern from rule file,value is the callsite
     */
    var constStringPatternMap: MutableMap<String, MutableSet<CallSite>> = HashMap()

    /**
     * key is a class,value is callsite of new instance
     */
    val newInstanceRefs: MutableMap<RefType, MutableSet<CallSite>> = HashMap()
    fun addMethodDirectCache(key: SootMethod, method: SootMethod, stmt: Stmt) {
        val cache = methodDirectRefs.computeIfAbsent(key) { HashSet() }
        cache.add(CallSite(method, stmt))
    }

    fun addMethodHeirCache(key: SootMethod, method: SootMethod, stmt: Stmt) {
        val cache = methodHeirRefs.computeIfAbsent(key) { HashSet() }
        cache.add(CallSite(method, stmt))
    }

    fun addLoadFieldCache(key: SootField, method: SootMethod, stmt: Stmt) {
        val cache = loadFieldRefs.computeIfAbsent(key) { HashSet() }
        cache.add(CallSite(method, stmt))
    }

    fun addStoreFieldCache(key: SootField, method: SootMethod, stmt: Stmt) {
        val cache = storeFieldRefs.computeIfAbsent(key) { HashSet() }
        cache.add(CallSite(method, stmt))
    }

    fun addNewInstanceCache(key: RefType, method: SootMethod, stmt: Stmt) {
        val cache = newInstanceRefs.computeIfAbsent(key) { HashSet() }
        cache.add(CallSite(method, stmt))
    }

    fun addPattern(pattern: String, method: SootMethod, stmt: Stmt) {
        val cache = constStringPatternMap.computeIfAbsent(pattern) { HashSet() }
        cache.add(CallSite(method, stmt))
    }


}