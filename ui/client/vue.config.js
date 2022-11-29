const path = require('path')
const isProduction = process.env.NODE_ENV !== 'development'

function resolvePath(dir) {
    return path.join(__dirname, '..', dir)
}

const CompressionWebpackPlugin = require('compression-webpack-plugin')
const UglifyJsPlugin = require('uglifyjs-webpack-plugin')

module.exports = {
    transpileDependencies: ['vue-echarts', 'resize-detector', 'element-ui', 'vuex', 'vue'],
    devServer: {
        open: true, //浏览器自动打开页面
        host: '0.0.0.0', //如果是真机测试，就使用这个IP
        port: 8912,
        https: false,
        disableHostCheck: true,
        hotOnly: false, //热更新（webpack已实现了，这里false即可）
        proxy: {
            //配置跨域
            '/': {
                // target: 'http://192.168.3.65:8081',
                target: 'http://81.69.7.178:8081',
                ws: true,
                changOrigin: true,
                pathRewrite: {
                    '^/api': '/'
                }
            }
        }
    },
    chainWebpack: (config) => {
        config.entry.app = ['babel-polyfill', './src/main.js']
        config.resolve.alias['@asset'] = resolvePath('src/assets')
        config.resolve.alias['@'] = resolvePath('src')
        config.module
            .rule('images')
            .use('image-webpack-loader')
            .loader('image-webpack-loader')
            .options({
                bypassOnDebug: true
            })
            .end()
    },
    configureWebpack: (config) => {
        if (isProduction) {
            // gzip压缩
            const productionGzipExtensions = ['html', 'js', 'css']
            config.plugins.push(
                    new CompressionWebpackPlugin({
                        filename: '[path].gz[query]',
                        algorithm: 'gzip',
                        test: new RegExp('\\.(' + productionGzipExtensions.join('|') + ')$'),
                        threshold: 10240, // 只有大小大于该值的资源会被处理 10240
                        minRatio: 0.8, // 只有压缩率小于这个值的资源才会被处理
                        deleteOriginalAssets: false // 删除原文件
                    })
                )
                //代码压缩
            config.plugins.push(
                    new UglifyJsPlugin({
                        uglifyOptions: {
                            //生产环境自动删除console
                            compress: {
                                //warnings: false, // 若打包错误，则注释这行
                                drop_debugger: true,
                                drop_console: true,
                                pure_funcs: ['console.log']
                            }
                        },
                        sourceMap: false,
                        parallel: true
                    })
                )
                // 公共代码抽离
            config.optimization = {
                splitChunks: {
                    cacheGroups: {
                        vendor: {
                            chunks: 'all',
                            test: /node_modules/,
                            name: 'vendor',
                            minChunks: 1,
                            maxInitialRequests: 5,
                            minSize: 0,
                            priority: 100
                        },
                        common: {
                            chunks: 'all',
                            test: /[\\/]src[\\/]js[\\/]/,
                            name: 'common',
                            minChunks: 2,
                            maxInitialRequests: 5,
                            minSize: 0,
                            priority: 60
                        },
                        styles: {
                            name: 'styles',
                            test: /\.(sa|sc|c)ss$/,
                            chunks: 'all',
                            enforce: true
                        },
                        runtimeChunk: {
                            name: 'manifest'
                        }
                    }
                }
            }
        }
    },
    publicPath: './',
    outputDir: 'dist', // 输出文件目录
    lintOnSave: false, // eslint 是否在保存时检查
    assetsDir: 'static', // 配置js、css静态资源二级目录的位置
    productionSourceMap: false
}