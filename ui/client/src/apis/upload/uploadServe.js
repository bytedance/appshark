import api from './../api'

// 通用上传接口
export const fileUpload = (params, callback, errCallback) => {
  serviceHandler('/file/upload', {
    params,
    callback,
    errCallback
  })
}
