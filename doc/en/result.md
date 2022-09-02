# Result interpretation

Results.json is designed to facilitate program processing rather than human reading. We focus on the SecurityInfo and ComplianceInfo fields.

## SecurityInfo

The security vulnerabilities here will be classified according to the `category` and `name` specified by the `desc` in the rule. It is convenient for program processing and manual reading.
The `vulners` field is a list of vulnerabilities of this type. Each of these vulnerabilities has a hash field, which can be treated as a unique identifier for the vulnerability.
The details field contains a lot of information about the vulnerability:

- Source: variables matching the source field in a rule
- Sink: variables matching the sink field in a rule
- position: the method where the source variable locates
- entryMethod: the entry of the analysis
- target: how the tainted data is propagated between variables
- url: use an HTML file to show how the tainted data is propagated between variables

## ComplianceInfo

ComplianceInfo is dedicated to privacy compliance issues. If the category is `ComplianceInfo`, then Appshark will process it specially. For example,

```json
{
  "desc": {
    "name": "GAID_NetworkTransfer_body",
    "detail": "There exists <GAID> obtaining operations sent over network-body",
    "category": "ComplianceInfo",
    "complianceCategory": "PersonalDeviceInformation_NetworkTransfer",
    "complianceCategoryDetail": "PersonalDeviceInformation_NetworkTransfer",
    "level": "3"
  }
}
```

Its classification is:

- The 1st level is ComplianceInfo
- The 2nd level is PersonalDeviceInformation_NetworkTransfer specified by ComplianceCategory
- The 3rd level is GAID_NetworkTransfer_body specified by name.

Another example:

```json
{
  "ComplianceInfo": {
    "PersonalDeviceInformation_NetworkTransfer": {
      "GAID_NetworkTransfer_body": {
        "category": "ComplianceInfo",
        "detail": "There exists <GAID> obtaining operations sent over network-body",
        "name": "GAID_NetworkTransfer_body",
        "vulners": [],
        "deobfApk": "",
        "level": "3"
      }
    }
  }
}
```

As for the field of vulners, its meaning is the same as that in SecurityInfo.

## Vulnerability details page introduction

The purpose of the vulnerability details page is designed to display information to users independently of the results.json file, so as to facilitate the root cause analysis of the vulnerability.

### vulnerability detail

It is the basic information of the app and its vulnerability.

### data flow

The target field mentioned above

### call stack

Methods that are involved in taint propagation.

### code detail

Show the process of taint propagation in detail. If javaSource is true in `config.json5`, the java code of the decompiled methods is also displayed.