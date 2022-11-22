const path = require("path");

const {
  createVuePlugin
} = require("vite-plugin-vue2");
import vueJsx from '@vitejs/plugin-vue-jsx'

function resolvePath(dir) {
  return path.join(__dirname, dir);
}

module.exports = {
  plugins: [vueJsx(), createVuePlugin(), ],
  base: "./",
  server: {
    open: true, //浏览器自动打开页面
    host: "0.0.0.0", //如果是真机测试，就使用这个IP
    port: 8912,
    https: false,
    disableHostCheck: true,
    hotOnly: true, //热更新（webpack已实现了，这里false即可）
    // proxy: {
    //     //配置跨域
    //     '/': {
    //         target: "http://192.168.1.190:7380",
    //         ws:true,
    //         changOrigin:true,
    //         pathRewrite:{
    //             '^/api':'/'
    //         }
    //     }
    // }
  },
  transpileDependencies: [
    'vue-echarts',
    'resize-detector'
  ],
  resolve: {
    alias: {
      "@": resolvePath("src"),
      "@/assets": resolvePath("src/assets"),
    },
  },
};