import Vue from 'vue'

/**
 * 格式化任务状态
 * */
Vue.filter('formatProcessStatus', function (status) {
  const statusMap = {
    WAITING: '未开始',
    PROCESSING: '进行中',
    FINISHED: '检测成功',
    ERROR: '检测失败'
  }
  return statusMap[status]
})
