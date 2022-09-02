# How does Appshard identify the privacy compliance issues in an app

Appshark can track data flows in an app, or identify the call site of an API call. Both features help you detect potential privacy compliance risks in your app. Privacy compliance-related rules are written in the same way as security vulnerability rules, so before you start, read [how_to_write_rules]().
## Privacy data flow analysis
Privacy data flow analysis is one of the data flow analyses. But most of the time you don't need to specify entry and sanitizer, you should care more about source and sink in rules.
Specifically, you can specify the source as an API obtaining private information. Say, 
```
"source": {
    "Return": [
        "<android.telephony.TelephonyManager: * getDeviceId(*)>"
    ]
}
```
This API's return value is the unique IMEI number of a device.
Specify the method you think will leak private data as a sink, such as writing to a file:
```
"sink": {
    "<java.io.FileOutputStream: * write(*)>": {
        "TaintCheck": [
            "p0"
        ]
    }
}
```
When the source of privacy data you are concerned about is not the API, but a field of an object, you can still write the rules according to the format of the field type source in the general rules, such as the device serial number as the source:
```
"source": {
    "Field": [
        "<android.os.Build: * SERIAL>"
    ]
}
```
At last, you need to use sliceMode to reduce the analysis time.


Full rule file:
```json
{
  "getDeviceId": {
    "SliceMode": true,
    "traceDepth": 8,
    "desc": {
      "name": "getDeviceId",
      "category": "ComplianceInfo",
      "detail": "",
      "wiki": "",
      "complianceCategory": "PersonalDeviceInformation",
      "complianceCategoryDetail": "PersonalDeviceInformation",
      "level": "3"
    },
    "source": {
      "Return": [
        "<android.telephony.TelephonyManager: * getDeviceId(*)>"
      ],
      "Field": [
        "<android.os.Build: * SERIAL>"
      ]
    },
    "sink": {
      "<java.io.FileOutputStream: * write(*)>": {
        "TaintCheck": [
          "p0"
        ]
      }
    }
  }
}
```
