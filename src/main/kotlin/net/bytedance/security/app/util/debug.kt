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

package net.bytedance.security.app.util

import soot.SootMethod

var dodebug = false
fun <T> toSorted(s: Set<T>): Set<T> {
    if (dodebug) {
        return s.toSortedSet(compareBy { it.toString() })
    }
    return s
}

fun <K, V> toSortedMap(s: Map<K, V>): Map<K, V> {
    if (dodebug) {
        return s.toSortedMap(compareBy { it.toString() })
    }
    return s
}


fun <V> toSortedMap2(s: Map<SootMethod, V>): Map<SootMethod, V> {
    if (dodebug) {
        return s.toSortedMap(compareBy { it.signature })
    }
    return s
}


fun <V> toSortedList(s: List<V>): List<V> {
    if (dodebug) {
        s.sortedWith(compareBy { it.toString() })
    }
    return s
}
