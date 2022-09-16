package net.bytedance.security.app.util

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.bytedance.security.app.RuleData
import net.bytedance.security.app.RuleDescription
import net.bytedance.security.app.SinkBody
import org.junit.jupiter.api.Test

@kotlinx.serialization.Serializable
data class CamilleData(
    var targetClass: String = "",
    var method: String = "",
    var action: String = "",
    var message: String = ""
)

class GenerateRuleTest {
    @Test
    fun generateRuleFromCamille() {
        //this data comes from https://github.com/zhengjim/camille/blob/master/script.js
        val data = """
            [
                {
                    "targetClass": "android.support.v4.app.ActivityCompat",
                    "method": "requestPermissions",
                    "action": "申请权限",
                    "message": "申请具体权限看\"参数1\""
                },
                {
                    "targetClass": "androidx.core.app.ActivityCompat",
                    "method": "requestPermissions",
                    "action": "申请权限",
                    "message": "申请具体权限看\"参数1\""
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getDeviceId",
                    "action": "获取电话相关信息",
                    "message": "获取IMEI"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getImei",
                    "action": "获取电话相关信息",
                    "message": "获取IMEI"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getMeid",
                    "action": "获取电话相关信息",
                    "message": "获取MEID"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getLine1Number",
                    "action": "获取电话相关信息",
                    "message": "获取电话号码标识符"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getSimSerialNumber",
                    "action": "获取电话相关信息",
                    "message": "获取IMSI/iccid"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getSubscriberId",
                    "action": "获取电话相关信息",
                    "message": "获取IMSI"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getSimOperator",
                    "action": "获取电话相关信息",
                    "message": "获取MCC/MNC"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getNetworkOperator",
                    "action": "获取电话相关信息",
                    "message": "获取MCC/MNC"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getSimCountryIso",
                    "action": "获取电话相关信息",
                    "message": "获取SIM卡国家代码"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getCellLocation",
                    "action": "获取电话相关信息",
                    "message": "获取电话当前位置信息"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getAllCellInfo",
                    "action": "获取电话相关信息",
                    "message": "获取电话当前位置信息"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "requestCellInfoUpdate",
                    "action": "获取电话相关信息",
                    "message": "获取基站信息"
                },
                {
                    "targetClass": "android.telephony.TelephonyManager",
                    "method": "getServiceState",
                    "action": "获取电话相关信息",
                    "message": "获取sim卡是否可用"
                },
                {
                    "targetClass": "android.telephony.cdma.CdmaCellLocation",
                    "method": "getBaseStationId",
                    "action": "获取电话相关信息",
                    "message": "获取基站cid信息"
                },
                {
                    "targetClass": "android.telephony.cdma.CdmaCellLocation",
                    "method": "getNetworkId",
                    "action": "获取电话相关信息",
                    "message": "获取基站lac信息"
                },
                {
                    "targetClass": "android.telephony.gsm.GsmCellLocation",
                    "method": "getCid",
                    "action": "获取电话相关信息",
                    "message": "获取基站cid信息"
                },
                {
                    "targetClass": "android.telephony.gsm.GsmCellLocation",
                    "method": "getLac",
                    "action": "获取电话相关信息",
                    "message": "获取基站lac信息"
                },
                {
                    "targetClass": "android.provider.SettingsSecure",
                    "method": "getString",
                    "action": "获取系统信息",
                    "message": "获取安卓ID"
                },
                {
                    "targetClass": "android.os.Build",
                    "method": "getSerial",
                    "action": "获取系统信息",
                    "message": "获取设备序列号"
                },
                {
                    "targetClass": "android.os.Build",
                    "method": "getSerial",
                    "action": "获取系统信息",
                    "message": "获取设备序列号"
                },
                {
                    "targetClass": "android.app.admin.DevicePolicyManager",
                    "method": "getWifiMacAddress",
                    "action": "获取系统信息",
                    "message": "获取mac地址"
                },
                {
                    "targetClass": "android.content.ClipboardManager",
                    "method": "getPrimaryClip",
                    "action": "获取系统信息",
                    "message": "读取剪切板信息"
                },
                {
                    "targetClass": "android.content.pm.PackageManager",
                    "method": "getInstalledPackages",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.content.pm.PackageManager",
                    "method": "getInstalledApplications",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.app.ApplicationPackageManager",
                    "method": "getInstalledPackages",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.app.ApplicationPackageManager",
                    "method": "getInstalledApplications",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.app.ApplicationPackageManager",
                    "method": "queryIntentActivities",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.app.ApplicationPackageManager",
                    "method": "getInstallerPackageName",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.app.ApplicationPackageManager",
                    "method": "getPackageInfoAsUser",
                    "action": "获取其他app信息",
                    "message": "APP获取了其他app信息"
                },
                {
                    "targetClass": "android.app.ActivityManager",
                    "method": "getRunningAppProcesses",
                    "action": "获取其他app信息",
                    "message": "获取了正在运行的App"
                },
                {
                    "targetClass": "android.location.LocationManager",
                    "method": "requestLocationUpdates",
                    "action": "获取位置信息",
                    "message": "获取位置信息"
                },
                {
                    "targetClass": "android.location.LocationManager",
                    "method": "getLastKnownLocation",
                    "action": "获取位置信息",
                    "message": "获取位置信息"
                },
                {
                    "targetClass": "android.net.wifi.WifiInfo",
                    "method": "getMacAddress",
                    "action": "获取网络信息",
                    "message": "获取Mac地址"
                },
                {
                    "targetClass": "android.net.wifi.WifiInfo",
                    "method": "getSSID",
                    "action": "获取网络信息",
                    "message": "获取wifi SSID"
                },
                {
                    "targetClass": "android.net.wifi.WifiInfo",
                    "method": "getBSSID",
                    "action": "获取网络信息",
                    "message": "获取wifi BSSID"
                },
                {
                    "targetClass": "android.net.wifi.WifiManager",
                    "method": "getConnectionInfo",
                    "action": "获取网络信息",
                    "message": "获取wifi信息"
                },
                {
                    "targetClass": "android.net.wifi.WifiManager",
                    "method": "getConfiguredNetworks",
                    "action": "获取网络信息",
                    "message": "获取wifi信息"
                },
                {
                    "targetClass": "android.net.wifi.WifiManager",
                    "method": "getScanResults",
                    "action": "获取网络信息",
                    "message": "获取wifi信息"
                },
                {
                    "targetClass": "java.net.InetAddress",
                    "method": "getHostAddress",
                    "action": "获取网络信息",
                    "message": "获取IP地址"
                },
                {
                    "targetClass": "java.net.NetworkInterface",
                    "method": "getHardwareAddress",
                    "action": "获取网络信息",
                    "message": "获取Mac地址"
                },
                {
                    "targetClass": "android.net.NetworkInfo",
                    "method": "getType",
                    "action": "获取网络信息",
                    "message": "获取网络类型"
                },
                {
                    "targetClass": "android.net.NetworkInfo",
                    "method": "getTypeName",
                    "action": "获取网络信息",
                    "message": "获取网络类型名称"
                },
                {
                    "targetClass": "android.net.NetworkInfo",
                    "method": "getExtraInfo",
                    "action": "获取网络信息",
                    "message": "获取网络名称"
                },
                {
                    "targetClass": "android.net.NetworkInfo",
                    "method": "isAvailable",
                    "action": "获取网络信息",
                    "message": "获取网络是否可用"
                },
                {
                    "targetClass": "android.net.NetworkInfo",
                    "method": "isConnected",
                    "action": "获取网络信息",
                    "message": "获取网络是否连接"
                },
                {
                    "targetClass": "android.hardware.Camera",
                    "method": "open",
                    "action": "调用摄像头",
                    "message": "调用摄像头"
                },
                {
                    "targetClass": "android.hardware.camera2.CameraManager",
                    "method": "openCamera",
                    "action": "调用摄像头",
                    "message": "调用摄像头"
                },
                {
                    "targetClass": "androidx.camera.core.ImageCapture",
                    "method": "takePicture",
                    "action": "调用摄像头",
                    "message": "调用摄像头拍照"
                },
                {
                    "targetClass": "android.bluetooth.BluetoothDevice",
                    "method": "getName",
                    "action": "获取蓝牙设备信息",
                    "message": "获取蓝牙设备名称"
                },
                {
                    "targetClass": "android.bluetooth.BluetoothDevice",
                    "method": "getAddress",
                    "action": "获取蓝牙设备信息",
                    "message": "获取蓝牙设备mac"
                },
                {
                    "targetClass": "android.bluetooth.BluetoothAdapter",
                    "method": "getName",
                    "action": "获取蓝牙设备信息",
                    "message": "获取蓝牙设备名称"
                }
            ]
        """.trimIndent()
        val format = Json {
            ignoreUnknownKeys = true
            prettyPrint = true
        }
        val camilleData: List<CamilleData> = format.decodeFromString(data)
        println(camilleData)
        //group by action
        val ruleMap = mutableMapOf<String, MutableList<CamilleData>>()
        for (c in camilleData) {
            val l = ruleMap.computeIfAbsent(c.action) { ArrayList() }
            l.add(c)
        }
        val rules = HashMap<String, RuleData>()
        for ((action, cs) in ruleMap) {
            val desc = RuleDescription(
                category = "camille",
                detail = action,
                name = action,
                complianceCategory = "ComplianceInfo"
            )
            val sinks = HashMap<String, SinkBody>()
            for (c in cs) {
                sinks["<${c.targetClass}: * ${c.method}(*)>"] = SinkBody()
            }
            val r = RuleData(desc = desc, APIMode = true, sink = sinks)
            rules[action] = r
        }
        println(format.encodeToString(rules))
    }
}