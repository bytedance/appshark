<template>
  <div>
    <div class="container">
      <div class="content">
        <el-form ref="newAddForm" label-width="0" :model="newAddParams" :rules="rules" @submit.native.prevent="sure">
          <el-form-item prop="password" class="w400 b-dib b-mr-20">
            <el-input
              v-model.trim="newAddParams.password"
              placeholder="如您不知道密码 请联系管理员"
              show-password
              clearable
              @keyup.enter="sure"
            ></el-input>
          </el-form-item>
          <el-button size="small" @click="sure" class="b-dib b-ml-20">
            <span class="b-dib" style="vertical-align: middle">
              <i class="iconfont icon-jurassic_next"></i>
              <span class="b-dib b-ml-5" style="margin-top: -1px">登 录</span>
            </span>
          </el-button>
        </el-form>
      </div>
    </div>
  </div>
</template>

<script>
import { normalLogin } from '@/apis/modules/login'
export default {
  name: 'index',
  data() {
    var validatePass = (rule, value, callback) => {
      if (!value) {
        return callback(new Error('请输入密码'))
      } else {
        callback()
      }
    }
    return {
      newAddParams: {
        password: '' // 密码
      },
      rules: {
        password: [{ validator: validatePass, trigger: 'blur' }]
      }
    }
  },
  methods: {
    sure() {
      this.$refs.newAddForm.validate((valid) => {
        if (valid) {
          let loading = this.$loading({ background: 'rgba(255, 255, 255, 0.9)' })
          normalLogin({ password: this.newAddParams.password }, (res) => {
            const { code, message } = res
            if (code !== '200') {
              this.$message.error(message)
              loading.close()
              return
            }
            localStorage.setItem('appShark_token', res.data.token)
            loading.close()
            this.$router.push({ name: 'list' })
          })
        }
      })
    }
  }
}
</script>

<style lang="scss" scoped>
.container {
  position: fixed;
  height: 100%;
  width: 100%;
  background-position: left center;
  background-repeat: no-repeat;
  background-size: cover;
  background-image: url(../assets/img/bg.png);
  .content {
    position: absolute;
    top: 40%;
    left: 50%;
    transform: translate(-50%, -40%);
    h3 {
      font-size: 40px;
      color: white;
      font-weight: bold;
    }
    .w400 {
      width: 400px;
    }
  }
}
.el-button--small {
  height: 36px;
  font-size: 14px;
}
</style>
