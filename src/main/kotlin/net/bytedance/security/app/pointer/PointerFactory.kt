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


package net.bytedance.security.app.pointer

import soot.*

/**
 * PLObject and PLPointer creator.
 *
 */
class PointerFactory {
    var ptrIndexMap: MutableMap<String, PLPointer> = HashMap()
    var objIndexMap: MutableMap<String, PLObject> = HashMap()

    /**
     * get or create a PLObject.
     * @param clsType type of this object, for example java.io.File
     * @param method where create this object
     * @param  site method and site Identify a unique object
     */
    fun allocObject(
        clsType: Type,
        method: SootMethod,
        v: Value?,
        site: Int
    ): PLObject {
        val classType = typeWrapper(clsType)
        val objSig = PLObject.getObjectSignature(classType, method, v, site)
        if (objIndexMap.containsKey(objSig)) {
            return objIndexMap[objSig]!!
        }

        val obj = PLObject(classType, method, site, objSig)
        objIndexMap[objSig] = obj
        return obj
    }

    /**
     * get or create a PLObject.
     * $r1=System.out
     * @param clsType type of this object
     * @param field the global static field
     * @param site, call site info
     */
    fun allocObjectByStaticField(
        clsType: Type,
        field: SootField,
        v: Value?,
        site: Int
    ): PLObject {
        val classType = typeWrapper(clsType)
        val objSig = PLObject.getObjectSignature(classType, field, v, site)
        if (objIndexMap.containsKey(objSig)) {
            return objIndexMap[objSig]!!
        }

        val obj = PLObject(classType, field, site, objSig)
        objIndexMap[objSig] = obj
        return obj
    }

    /**
     * get or create a PLPtrLocal
     * @param method which  this pointer belongs to
     * @param localName of this variable,for example r0,$r1, or @const_str:some_string
     * @param origType type of this variable,for example java.io.File
     */
    fun allocLocal(
        method: SootMethod,
        localName: String,
        origType: Type
    ): PLLocalPointer {
        val ptrSig =
            PLLocalPointer.getPointerLocalSignature(method, localName)
        if (ptrIndexMap.containsKey(ptrSig)) {
            return ptrIndexMap[ptrSig] as PLLocalPointer
        }
        val ptr = PLLocalPointer(method, localName, origType, ptrSig)
        ptrIndexMap[ptrSig] = ptr

        return ptr
    }

    //for test only
    @Suppress("unused")
    fun testGetLocal(methodSignature: String, localName: String): PLPointer? {
        val method = Scene.v().getMethod(methodSignature) ?: return null
        val ptrSig =
            PLLocalPointer.getPointerLocalSignature(method, localName)
        return ptrIndexMap[ptrSig]
    }

    /**
     * get or create a PLPtrObjectField
     * @param obj  object this field belongs to
     * @param fieldName name of this field, maybe @data to represent all the field
     * @param fieldType type of this field
     * @param sootField
     */
    fun allocObjectField(
        obj: PLObject,
        fieldName: String,
        fieldType: Type,
        sootField: SootField? = null
    ): PLPtrObjectField {
        val ptrSig = getObjectFieldShortSignature(obj, fieldType, fieldName)
        if (ptrIndexMap.containsKey(ptrSig)) {
            return ptrIndexMap[ptrSig] as PLPtrObjectField
        }
        val ptr = PLPtrObjectField(obj, fieldName, fieldType, sootField, ptrSig)
        ptrIndexMap[ptrSig] = ptr
        return ptr
    }

    /**
     * get or create a PLPtrObjectField for @data
     */
    fun allocObjectField(
        obj: PLObject,
        fieldName: String,
        type: Type
    ): PLPtrObjectField {
        val elemType: Type = if (type is ArrayType) {
            type.elementType
        } else {
            type
        }
        return allocObjectField(obj, fieldName, elemType, null)
    }

    /**
     * get or create a PLPtrStaticField
     */
    fun allocStaticField(staticField: SootField): PLPtrStaticField {
        val sig = staticField.shortSignature()
        if (ptrIndexMap.containsKey(sig)) {
            return ptrIndexMap[sig] as PLPtrStaticField
        }
        val ptr = PLPtrStaticField(staticField)
        ptrIndexMap[sig] = ptr
        return ptr
    }

    companion object {
        fun getObjectFieldSignature(obj: PLObject, fieldType: Type, fieldName: String): String {
            return "pf{${obj.longSignature()}($fieldType)->$fieldName}"
        }

        fun getObjectFieldShortSignature(obj: PLObject, fieldType: Type, fieldName: String): String {
            return "pf{${obj.signature}(${fieldType.shortName()})->$fieldName}"
        }

        fun typeWrapper(type: Type): Type {
            return if (type is ArrayType && type.numDimensions > 1) {
                ArrayType.v(type.baseType, 1)
            } else type
        }
    }
}