import Vue from 'vue'
import App from './App.vue'
import router from './router'

import './assets/scss/common.scss'
import 'element-ui/lib/theme-chalk/index.css'
import '@/assets/styles/index.scss' // global css
import 'amfe-flexible'

import ElementUI from 'element-ui'

Vue.use(ElementUI)

import api from './apis/api'
Vue.prototype.$api = api

import '@/filter/index'

import store from './store'

import common from './apis/common/common.js'
Vue.prototype.$common = common

Vue.config.productionTip = false

import '@/assets/icon/iconfont.css'

new Vue({
  router,
  store,
  render: (h) => h(App)
}).$mount('#app')
