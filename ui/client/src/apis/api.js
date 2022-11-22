/* eslint-disable */

import axios from 'axios/index'
import ElementUI from 'element-ui'
import store from '../store'

import router from '@/router'
let api = {}

import { Loading } from 'element-ui'
let loadingInstance = null
let errorLoading = true

import { getToken } from '@/utils/auth'
/*
 * 设置请求限制
 * */

// 在main.js设置全局的请求次数，请求的间隙
axios.defaults.retry = 1
axios.defaults.retryDelay = 500

// 创建axios实例 axiso的一些基础参数配置,
const service = axios.create({
  withCredentials: true,
  baseURL: process.env.VUE_APP_BASE_API, // 配置在config/prod.env里的baseApi
  timeout: 15 * 24 * 60 * 60 * 1000 // 超时时间
})

// 清除用户信息
function clearUserInfo() {
  localStorage.setItem('appShark_token', '')
  Object.keys(store.getters.selectedColumns).forEach((item) => {
    store.commit('SET_COLUMNS', { key: item, data: [] })
  })
}

// POST 传参序列化
service.interceptors.request.use(
  function (config) {
    let token = getToken()
    if (token) {
      config.headers.Authorization = token
    }
    /*noLoadingApiList.some(item => {
                  if (config.url.indexOf(item) === -1) {
                    loadingInstance = Loading.service({ fullscreen: true })
                    return true
                  }
                })*/
    return config
  },
  function (error) {
    return Promise.reject(error)
  }
)

//返回状态判断(添加响应拦截器)
service.interceptors.response.use(
  (res) => {
    if (res.data.code === '200') {
      return res
    } else if (res.data.code === '401' || res.code === '401') {
      if (errorLoading) {
        Loading.service({ fullscreen: true }).close()
        errorLoading = false
        ElementUI.Message({
          type: 'error',
          message: '登录超时,请重新登录'
        })
        clearUserInfo() // 清除用户信息
        router.push({
          path: '/index'
        })
        return Promise.reject(res)
      }
    } else {
      return res
    }
  },
  (error) => {
    if (error.response.status === 401) {
      if (errorLoading) {
        errorLoading = false
        Loading.service({ fullscreen: true }).close()
        ElementUI.Message({
          type: 'error',
          message: '登录超时,请重新登录'
        })
        setTimeout(() => {
          errorLoading = true
        }, 3000)
        clearUserInfo() // 清除用户信息
        router.push({
          path: '/index'
        })
      }
    } else {
      // 服务器错误
      ElementUI.Message({
        type: 'error',
        message: error
      })
      return Promise.reject(error.response.data)
    }
    // 返回 response 里的错误信息
    return Promise.reject(error.response.data)
  }
)

// 主服务处理函数 - POST
api.serviceHandler = (serverUrl, { params, callback, errCallback }) => {
  if (Object.prototype.toString.call(params) === '[object Object]' || typeof params == 'object') {
    return service
      .post(serverUrl, params)
      .then((data) => {
        callback && callback(data.data)
      })
      .catch((error) => {
        errCallback && errCallback(error)
      })
  } else {
    return service
      .post(serverUrl + '/' + params)
      .then((data) => {
        callback && callback(data.data)
      })
      .catch((error) => {
        errCallback && errCallback(error)
      })
  }
}
service.interceptors.response.use(undefined, function axiosRetryInterceptor(err) {
  var config = err.config
  if (!config || !config.retry) return Promise.reject(err)
  config.__retryCount = config.__retryCount || 0
  if (config.__retryCount >= config.retry) {
    return Promise.reject(err)
  }
  config.__retryCount += 1
  var backoff = new Promise(function (resolve) {
    setTimeout(function () {
      resolve()
    }, config.retryDelay || 1)
  })
  return backoff.then(function () {
    return axios(config)
  })
})
// 主服务处理函数 - GET
api.serviceGetHandler = (serverUrl, { params, callback, errCallback }) => {
  let dataParams = ''
  if (Object.prototype.toString.call(params) === '[object Object]') {
    for (let key in params) {
      if (dataParams) {
        dataParams += '&'
      }
      dataParams += encodeURIComponent(key) + '=' + encodeURIComponent(params[key])
    }
    if (dataParams) dataParams = '?' + dataParams + '&t=' + new Date().getTime()
  } else {
    dataParams = '/' + params + '?t=' + new Date().getTime()
  }
  return service
    .get(serverUrl + dataParams)
    .then((data) => {
      callback && callback(data.data)
    })
    .catch((error) => {
      errCallback && errCallback(error)
    })
}

// 全局下载二进制流文件
api.downLoadFileByName = (params, callback) => {
  service({
    url: '/file/download',
    method: 'post',
    data: params,
    responseType: 'arraybuffer'
  }).then((res) => {
    callback(res)
  })
}

export default api
