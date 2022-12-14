/* eslint-disable no-inner-declarations */
/**
 * Created by jiachenpan on 16/11/18.
 */

// 文件名校验
export const fileNameValide = (fileName) => {
  // let reg = /^[a-zA-Z0-9-_.\u4e00-\u9fa5]{1,}$/
  let reg = /^[a-zA-Z0-9-_.\u4e00-\u9fa5（）()-]{1,}$/
  if (reg.test(fileName)) {
    return true
  } else {
    return false
  }
}
