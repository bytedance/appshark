import api from '../api'

// 登录
export const normalLogin = (params, callback, errCallback) => {
  api.serviceHandler('/login/normalLogin', {
    params,
    callback,
    errCallback
  })
}

// 任务列表分页
export const queryByPage = (params, callback, errCallback) => {
  api.serviceHandler('/assignment/queryByPage', {
    params,
    callback,
    errCallback
  })
}

// 上传规则文件
export const uploadRules = (params, callback, errCallback) => {
  api.serviceHandler('/file/uploadRules', {
    params,
    callback,
    errCallback
  })
}

// 检测任务删除
export const batchRemove = (params, callback, errCallback) => {
  api.serviceHandler('/assignment/batchRemove', {
    params,
    callback,
    errCallback
  })
}

// 获取所有规则
export const getAllRules = (params, callback, errCallback) => {
  api.serviceGetHandler('/appShark/getAllRules', {
    params,
    callback,
    errCallback
  })
}

// 上传APP文件
export const uploadApp = (params, callback, errCallback) => {
  api.serviceHandler('/file/uploadApp', {
    params,
    callback,
    errCallback
  })
}

// 新增扫描任务
export const save = (params, callback, errCallback) => {
  api.serviceHandler('/assignment/save', {
    params,
    callback,
    errCallback
  })
}
