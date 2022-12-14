/* eslint-disable */
import Vue from 'vue'
import api from './../api'

let timer = null
let common = {
  win_origin: window.location.origin + window.location.pathname
}

common.spinTime = 0
common.maxSpinTime = 5000

common.deepClone = function (origin, target, filter) {
  var toStr = Object.prototype.toString,
    arrStr = '[object Array]',
    target = target || (toStr.call(origin) === arrStr ? [] : {})
  for (let prop in origin) {
    if (filter) {
      if (prop === filter) {
        break
      }
    }
    if (origin.hasOwnProperty(prop)) {
      if (origin[prop] !== null && typeof origin[prop] === 'object') {
        if (toStr.call(origin[prop]) === arrStr) {
          target[prop] = []
        } else {
          target[prop] = {}
        }
        common.deepClone(origin[prop], target[prop], filter)
      } else {
        target[prop] = origin[prop]
      }
    }
  }
  return target
}

export default common
