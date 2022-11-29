import api from '../api'

// 详情
export const assignmentDetail = (params, callback, errCallback) => {
        api.serviceGetHandler('/assignment/detail', {
            params,
            callback,
            errCallback
        })
    }
    // 权限清单统计
export const permissionList = (params, callback, errCallback) => {
        api.serviceHandler('/assignment/permission/queryByPage', {
            params,
            callback,
            errCallback
        })
    }
    // 任务详情合规检测分页查询
export const complianceList = (params, callback, errCallback) => {
        api.serviceHandler('/assignment/compliance/queryByPage', {
            params,
            callback,
            errCallback
        })
    }
    // 查询合规检测扫描类型
export const queryCamilleMap = (params, callback, errCallback) => {
        api.serviceGetHandler('/assignment/compliance/queryCamilleMap', {
            params,
            callback,
            errCallback
        })
    }
    // 漏洞统计图
export const statisticsType = (params, callback, errCallback) => {
        api.serviceHandler('/assignment/vulner/statisticsType', {
            params,
            callback,
            errCallback
        })
    }
    // 漏洞统计分页
export const vulnerList = (params, callback, errCallback) => {
        api.serviceHandler('/assignment/vulner/queryByPage', {
            params,
            callback,
            errCallback
        })
    }
    // 扫描报告导出
export const exportScanReport = (params, callback, errCallback) => {
    api.serviceGetHandler('/file/export/exportScanReport', {
        params,
        callback,
        errCallback
    })
}