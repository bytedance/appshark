import Vue from 'vue'
import VueRouter from 'vue-router'
import version from '@/page/version'
Vue.use(VueRouter)

const Index = () =>
    import ( /* webpackChunkName: "appshark" */ '../page/index.vue')
const Layout = () =>
    import ( /* webpackChunkName: "appshark" */ '../page/Layout')
const List = () =>
    import ( /* webpackChunkName: "appshark" */ '../page/list')
const Add = () =>
    import ( /* webpackChunkName: "appshark" */ '../page/add')
const Rules = () =>
    import ( /* webpackChunkName: "appshark" */ '../page/Layout/rules.vue')

const routes = [{
        path: '/index',
        name: 'index',
        component: Index
    },
    {
        path: '',
        redirect: '/list',
        name: 'version',
        component: version,
        children: [{
                path: '/layout',
                name: 'Layout',
                component: Layout,
                meta: { requireAuth: true }
            },
            {
                path: '/list',
                name: 'list',
                component: List,
                meta: { requireAuth: true }
            },
            {
                path: '/add',
                name: 'add',
                component: Add,
                meta: { requireAuth: true }
            },
            {
                path: '/rules',
                name: 'rules',
                component: Rules,
                meta: { requireAuth: true }
            }
        ]
    }
]

const router = new VueRouter({
    routes
})

router.beforeEach((to, from, next) => {
    if (to.meta.requireAuth) {
        // 需要权限
        //判断当前是否拥有权限
        if (localStorage.getItem('appShark_token')) {
            next()
        } else {
            // 无权，跳转登录
            next({
                path: '/index'
            })
        }
    } else {
        if (localStorage.getItem('appShark_token')) {
            next('/list')
        } else {
            // 不需要权限，直接访问
            next()
        }
    }
})

export default router