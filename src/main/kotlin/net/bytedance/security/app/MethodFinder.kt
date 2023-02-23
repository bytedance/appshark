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


package net.bytedance.security.app

import net.bytedance.security.app.preprocess.MethodFieldConstCacheVisitor
import net.bytedance.security.app.util.newFieldSignature
import net.bytedance.security.app.util.newFunctionSignature
import net.bytedance.security.app.util.profiler
import net.bytedance.security.app.util.subSignature
import soot.Scene
import soot.SootClass
import soot.SootField
import soot.SootMethod

/**
 *  find a specific method
 */
object MethodFinder {
    /**
     *@param pattern:  a*, *a,aa*a,*
     *@param target: string to match
     */
    fun isMatched(pattern: String, target: String): Boolean {
        var pattern2 = pattern
        var target2 = target
        if (pattern2 == "*") {
            return true
        }
        pattern2 = pattern2.lowercase()
        target2 = target2.lowercase()
        return if (pattern2.startsWith("*") && pattern2.endsWith("*")) {
            val patternStr = pattern2.split("\\*".toRegex()).toTypedArray()[1]
            if (patternStr.isEmpty()) {
                Log.logFatal("Format Error $pattern2")
            }
            target2.contains(patternStr)
        } else if (pattern2.startsWith("*")) {
            val partTargetStr = pattern2.split("\\*".toRegex()).toTypedArray()[1]
            if (partTargetStr.isEmpty()) {
                Log.logFatal("Format Error $pattern2")
            }
            target2.endsWith(partTargetStr)
        } else if (pattern2.endsWith("*")) {
            val partTargetStr = pattern2.split("\\*".toRegex()).toTypedArray()[0]
            if (partTargetStr.isEmpty()) {
                Log.logFatal("Format Error $pattern2")
            }
            target2.startsWith(partTargetStr)
        } else {
            target2 == pattern2
        }
    }

    private fun addMatchedMethodSet(possibleMethodSigSet: MutableSet<SootMethod>, sm: SootMethod) {
        if (!MethodFieldConstCacheVisitor.canMethodHasSubMethods(sm)) {
            possibleMethodSigSet.add(sm)
            return
        }
        val sc = sm.declaringClass
        val subClassSet = HashSet<SootClass>()
        PLUtils.getAllSubCLass(sc, subClassSet)
        for (sootClass in subClassSet) {
            val subMethod = sootClass.getMethodUnsafe(sm.subSignature)
            if (subMethod != null) {
                possibleMethodSigSet.add(subMethod)
            }

        }
    }

    private fun filterByClassName(className: String): Collection<SootClass> {
        val results = ArrayList<SootClass>()
        //to avoid java.util.ConcurrentModificationException
        for (c in PLUtils.classes) {
            if (isMatched(className, c.name)) {
                results.add(c)
            }
        }
        return results
    }

    /**
     * @param methodSig  something like :<*: void onCreate(android.os.Bundle)>
     * @return  returns all matched methods
     * prerequisite :
     * 1. partial matching of class names is not supported, for example: com.security.Command*
     * 2. If the class name is explicit, it will match all subclasses
     */
    @Synchronized
    private fun checkAndParseMethodSigInternal(methodSig: String): Set<SootMethod> {
        val matchedMethodSet: MutableSet<SootMethod> = HashSet()
        val fd = newFunctionSignature(methodSig)
        if (!fd.className.contains("*") && !fd.functionName.contains("*") && !fd.args.contains("*") && !fd.returnType.contains(
                "*"
            )
        ) {
            val sc = Scene.v().getSootClassUnsafe(fd.className, false)
            val sm = Scene.v().grabMethod(methodSig)
            if (sc != null && sm != null) {
                matchedMethodSet.add(sm)
                val subClassSet = HashSet<SootClass>()
                PLUtils.getAllSubCLass(sc, subClassSet)
                for (sootClass in subClassSet) {
                    val subMethod = sootClass.getMethodUnsafe(sm.subSignature)
                    if (subMethod != null) {
                        matchedMethodSet.add(subMethod)
                    }
                }
            }

            return matchedMethodSet
        }
        val targetClassSet = getClassesByName(fd.className)
        val possibleMethodSigSet: MutableSet<SootMethod> = HashSet()
        for (sc in targetClassSet) {
            var methods: List<SootMethod>
            if (sc.name.startsWith(PLUtils.CUSTOM_CLASS)) {
                continue
            } else {
                methods = sc.methods
            }
            if (fd.functionName.contains("*") || fd.args.contains("*") || fd.returnType.contains("*")) {
                if (fd.functionName == "*") {
                    methods.forEach {
                        matchedMethodSet.add(it)
                        addMatchedMethodSet(possibleMethodSigSet, it)
                    }
                } else {
                    for (sm in methods) {
                        if (isMatched(fd.functionName, sm.name)) {
                            matchedMethodSet.add(sm)
                            addMatchedMethodSet(possibleMethodSigSet, sm)
                        }
                    }
                }
            } else {
                for (sm in methods) {
                    if (fd.subSignature() == sm.subSignature) {
                        matchedMethodSet.add(sm)
                        addMatchedMethodSet(possibleMethodSigSet, sm)
                    }
                }
            }
        }

        for (otherSig in possibleMethodSigSet) {
            matchedMethodSet.add(otherSig)
        }
        Log.logDebug(methodSig + " Parsed " + matchedMethodSet.size)
        return matchedMethodSet
    }

    /**
     * cache for checkAndParseMethodSigInternal
     */
    private var MethodSignatureCache: MutableMap<String, Set<SootMethod>> = HashMap()
    private var FieldSignatureCache: MutableMap<String, Set<SootField>> = HashMap()

    @Synchronized
    fun checkAndParseMethodSig(methodSig: String): Set<SootMethod> {
        if (MethodSignatureCache.containsKey(methodSig)) {
            return MethodSignatureCache[methodSig]!!
        }
        val start = System.currentTimeMillis()
        val s = checkAndParseMethodSigInternal(methodSig)
        profiler.checkAndParseMethodSigInternalTake(System.currentTimeMillis() - start)
        MethodSignatureCache[methodSig] = s
        return s
    }

    @Synchronized
    fun clearCache() {
        MethodSignatureCache.clear()
        FieldSignatureCache.clear()
    }

    /**
     * find fields by filed pattern like:
     * <android.provider.VoicemailContract*: android.net.Uri *>
     */
    @Synchronized
    fun checkAndParseFieldSignature(fieldSignature: String): Set<SootField> {
        if (FieldSignatureCache.containsKey(fieldSignature)) {
            return FieldSignatureCache[fieldSignature]!!
        }
        val start = System.currentTimeMillis()
        val s = checkAndParseFieldSignatureInternal(fieldSignature)
        profiler.checkAndParseMethodSigInternalTake(System.currentTimeMillis() - start)

        FieldSignatureCache[fieldSignature] = s
        return s
    }

    @Synchronized
    private fun checkAndParseFieldSignatureInternal(fieldSignature: String): Set<SootField> {
        val matchedFieldSet: MutableSet<SootField> = HashSet()
        val fd = newFieldSignature(fieldSignature)
        //1. If it does not contain a *, it is an exact match.
        if (!fd.className.contains("*") && !fd.fieldName.contains("*") && !fd.fieldType.contains("*")) {
            val sc = Scene.v().getSootClassUnsafe(fd.className, false)
            val sf = Scene.v().grabField(fieldSignature)
            if (sc != null && sf != null) {
                matchedFieldSet.add(sf)
            }
            return matchedFieldSet
        }
        //2. If it contains *, pattern matching is required
        val targetClassSet = getClassesByName(fd.className)

        //2.2 field by field, you don't have to worry about subclasses like method
        for (cls in targetClassSet) {
            for (sf in cls.fields) {
                if (isMatched(fd.fieldName, sf.name) && isMatched(fd.fieldType, sf.type.toString())) {
                    matchedFieldSet.add(sf)
                }
            }
        }
        return matchedFieldSet
    }

    /**
     * pattern matching based on class name
     */
    private fun getClassesByName(className: String): Collection<SootClass> {
        return if (className == "*") {
            PLUtils.classes
        } else {
            if (className.indexOf("*") >= 0) {
                return filterByClassName(className)
            } else {
                val sc = Scene.v().getSootClassUnsafe(className, false) ?: return setOf()
                return setOf(sc)
            }
        }
    }
}