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


package net.bytedance.security.app.android

import soot.Scene
import soot.SootClass

/*
Calculate the inheritable functions of the android component classes to
facilitate the automatic generation of Entry functions
 */
object LifecycleConst {
    var ActivityClass: SootClass = Scene.v().getSootClassUnsafe(
        "android.app.Activity", false
    )
    var ServiceClass: SootClass = Scene.v().getSootClassUnsafe(
        "android.app.Service", false
    )

    @Suppress("unused")
    var IntentServiceClass: SootClass = Scene.v().getSootClassUnsafe(
        "android.app.IntentService", false
    )
    var BroadcastReceiverClass: SootClass = Scene.v().getSootClassUnsafe(
        "android.content.BroadcastReceiver", false
    )
    var ContentProviderClass: SootClass = Scene.v().getSootClassUnsafe(
        "android.content.ContentProvider", false
    )
    var FragmentClass: SootClass? = Scene.v().getSootClassUnsafe(
        "androidx.fragment.app.Fragment", false
    )

    /**
     *all the overridable methods of android.app.Activity
     */
    val ActivityMethods = listOf(
        "void onBackPressed()",
        "void onCreate(android.os.Bundle)",
        "void onDestroy()",
        "void onPause()",
        "void onRestart()",
        "void onResume()",
        "void onStart()",
        "void onStop()",
        "void onSaveInstanceState(android.os.Bundle)",
        "void onRestoreInstanceState(android.os.Bundle)",
        "java.lang.CharSequence onCreateDescription()",
        "void onPostCreate(android.os.Bundle)",
        "void onPostResume()",
        "void onAttachFragment(android.app.Fragment)"
    )

    /**
     * all the overridable methods of android.app.IntentService/android.app.Service
     */
    val ServiceMethods = listOf(
        "void onCreate()",
        "void onStart(android.content.Intent,int)",
        "int onStartCommand(android.content.Intent,int,int)",
        "android.os.IBinder onBind(android.content.Intent)",
        "void onRebind(android.content.Intent)",
        "boolean onUnbind(android.content.Intent)",
        "void onDestroy()",
    )

    /**
     * all the overridable methods of android.content.BroadcastReceiver
     */
    val BroadcastReceiverMethods = listOf(
        "void onReceive(android.content.Context,android.content.Intent)",
    )

    /**
     * all the overridable methods of android.content.ContentProvider
     */
    val ProviderMethods = listOf(
        "boolean onCreate()",
    )
    val FragmentMethods = listOf(
        "android.view.View onCreateView(android.view.LayoutInflater,android.view.ViewGroup,android.os.Bundle)",
        "void onAttach(android.content.Context)",
        "void onAttach(android.app.Activity)",
        "void onCreate(android.os.Bundle)",
        "void onViewCreated(android.view.View,android.os.Bundle)",
        "void onStart()",
        "void onResume()",
        "void onPause()",
        "void onStop()",
        "void onDestroyView()",
        "void onDestroy()",
        "void onDetach()",
        "void onActivityCreated(android.os.Bundle)",
        "void onActivityResult(int,int,android.content.Intent)",
        "void onAttachFragment(androidx.fragment.app.Fragment)",
    )

    /**
     * return true when sc is an android component class
     */
    fun isComponentClass(sc: SootClass): Boolean {
        val classes = mutableListOf(
            ActivityClass,
            ServiceClass,
            BroadcastReceiverClass,
            BroadcastReceiverClass,
            FragmentClass,
            ContentProviderClass
        )
        if (FragmentClass != null) {
            classes.add(FragmentClass)
        }
        classes.any {
            it != null && isSubClass(sc, it)
        }
        return false
    }

    /**
     *   returns true if ancestor has an ancestor relationship with child, false otherwise
     */
    fun isSubClass(child: SootClass, ancestor: SootClass): Boolean {
        if (child == ancestor) {
            return true
        }
        if (child.hasSuperclass()) {
            return isSubClass(child.superclass, ancestor)
        }
        return false
    }

}
