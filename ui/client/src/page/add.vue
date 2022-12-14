<template>
  <div class="box-container default-box">
    <el-form label-width="120px" :model="addParams" ref="addFormRef" :rules="rules">
      <el-card class="box-card default-card">
        <div slot="header">
          <span>填写任务基本信息</span>
        </div>
        <el-form-item label="任务名称:" prop="assignmentName">
          <el-input
            type="text"
            v-model.trim="addParams.assignmentName"
            placeholder="请输入任务名称"
            clearable
            maxLength="20"
            style="width: 500px"
          ></el-input>
        </el-form-item>
        <el-form-item label="任务描述:" prop="assignmentDescription" class="b-mt-20">
          <el-input
            type="textarea"
            v-model.trim="addParams.assignmentDescription"
            placeholder="请输入任务描述"
            maxLength="500"
            :autosize="{ minRows: 3, maxRows: 6 }"
          ></el-input>
        </el-form-item>
      </el-card>
      <el-card class="box-card default-card b-mt-10">
        <div slot="header">
          <span>检测信息配置</span>
        </div>
        <el-form-item label="上传App文件:" class="upload">
          <el-upload
            ref="uploadFile"
            action=""
            :http-request="uploadRequest"
            :file-list="fileList"
            :limit="1"
            :on-exceed="fileExceed"
            :on-remove="fileRemove"
          >
            <el-button size="small" type="default">选取文件</el-button>
            <span slot="tip" class="el-upload__tip grey b-ml-20">仅支持上传apk格式文件，且文件不超过5个G</span>
          </el-upload>
        </el-form-item>
        <el-form-item label="选择规则:" prop="preRules">
          <el-checkbox-group v-model="addParams.preRules">
            <!-- <el-checkbox v-for="item in ruleList" :key="item.label" :label="item.label"></el-checkbox> -->
            <div v-for="item in ruleList" :key="item.label" class="b-mr-20">
              <el-checkbox :label="item.label">
                <p @click="lookRule(item.label)">{{ item.label }}</p>
              </el-checkbox>
            </div>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="最大点分析时间:" prop="largestAnalysis" class="b-mt-20">
          <el-input
            type="text"
            v-model.trim="addParams.largestAnalysis"
            placeholder="请输入正整数，时间以秒为单位"
            style="width: 300px"
            maxlength="7"
          ></el-input>
          <el-tooltip class="tooltip b-ml-20" effect="dark" placement="right">
            <div slot="content">默认值为600秒，数值越大，分析时间越长，分析结果也更为全面</div>
            <i class="el-icon-question gutter"></i>
          </el-tooltip>
        </el-form-item>
      </el-card>
    </el-form>
    <div class="f-tac b-mt-20">
      <el-button size="small" @click="goBack"> 返 回</el-button>
      <el-button type="primary" size="small" @click="sure" style="margin-left: 20px">确认完成</el-button>
    </div>
  </div>
</template>

<script>
import { getAllRules, uploadApp, save } from '@/apis/modules/login'
export default {
  name: 'add',
  data() {
    var checkTime = (rule, value, callback) => {
      if (/^[1-9]+[0-9]*$/.test(value) === false && value) {
        return callback(new Error('请输入正整数'))
      } else if (value > 1296000 && value) {
        return callback(new Error('最大值为1296000s（15天）'))
      } else {
        callback()
      }
    }
    return {
      addParams: {
        assignmentName: '', // 任务名称
        assignmentDescription: '', // 任务描述
        appAttachId: '', // app文件id
        preRules: [],
        largestAnalysis: '' // 最大点分析时间
      },
      rules: {
        assignmentName: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
        preRules: [{ type: 'array', required: true, message: '请至少选择一个规则', trigger: 'change' }],
        largestAnalysis: [{ validator: checkTime, trigger: 'blur' }]
      },
      ruleList: [], // 规则列表
      fileList: []
    }
  },
  mounted() {
    this.getAllRules() // 获取所有规则
  },
  methods: {
    // 获取所有规则
    getAllRules() {
      getAllRules({}, (res) => {
        const { code, message } = res
        if (code !== '200') {
          this.$message.error(message)
          return
        }
        let data = res.data || []
        this.ruleList = data.map((item) => {
          return {
            value: item,
            label: item
          }
        })
      })
    },
    // 上传文件超出上传个数
    fileExceed() {
      this.$message.error('一次仅支持上传一个文件')
    },
    // 文件列表移除文件时的钩子
    fileRemove() {
      this.addParams.appAttachId = '' // app文件id
    },
    // 上传apk文件
    uploadRequest(res) {
      const file = res.file
      var testmsg = file.name.substring(file.name.lastIndexOf('.') + 1)
      if (testmsg !== 'apk') {
        this.$message({ message: '仅支持上传apk格式文件', type: 'error' })
        let uid = file.uid
        let idx = this.$refs.uploadFile.uploadFiles.findIndex((item) => item.uid === uid)
        this.$refs.uploadFile.uploadFiles.splice(idx, 1)
        return
      }
      // 限制文件大小
      if (file.size / (1024 * 1024) > 1024 * 5) {
        this.$message({ message: '上传失败！文件超过5个G', type: 'error' })
        let uid = file.uid
        let idx = this.$refs.uploadFile.uploadFiles.findIndex((item) => item.uid === uid)
        this.$refs.uploadFile.uploadFiles.splice(idx, 1)
        return
      }
      let messageInfo = this.$message({
        showClose: false,
        message: `${res.file.name}文件上传中...`,
        duration: 0
      })
      let formData = new FormData()
      formData.append('file', file)
      uploadApp(formData, (res) => {
        const { code, message } = res
        if (code !== '200') {
          this.$message.error(message)
          messageInfo.close()
          return
        }
        this.addParams.appAttachId = res.data.fileId // app文件id
        messageInfo.close()
        this.$message({ type: 'success', message: '上传成功' })
      })
    },
    // 返回
    goBack() {
      this.$router.push({ name: 'list' })
    },
    // 确认
    sure() {
      this.$refs.addFormRef.validate((valid) => {
        if (valid) {
          if (!this.addParams.appAttachId) {
            this.$message.error('请上传App文件')
            return
          }
          let loading = this.$loading({ background: 'rgba(255, 255, 255, 0.9)' })
          // 最大点分析时间默认为600s
          this.addParams.largestAnalysis = this.addParams.largestAnalysis ? this.addParams.largestAnalysis : '600'
          save(this.addParams, (res) => {
            const { code, message } = res
            if (code !== '200') {
              this.$message.error(message)
              loading.close()
              return
            }
            loading.close()
            this.$router.push({ name: 'list' })
          })
        }
      })
    },
    lookRule(name) {
      window.open(`http://81.69.7.178:8080/root/appshark/config/rules/${name}`, '_blank')
    }
  }
}
</script>

<style lang="scss" scoped>
.box-container {
  min-height: calc(100% - 100px);
  box-shadow: 1px 1px 4px 0 rgb(72 99 129 / 20%);
  border-radius: 0 8px 8px 8px;
  padding: 14px;
  box-sizing: border-box;
  background-color: #eaedf7;
}
.upload ::v-deep label.el-form-item__label:before {
  content: '*';
  color: #f56c6c;
  margin-right: 4px;
}
::v-deep .el-textarea__inner {
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', '微软雅黑', Arial,
    sans-serif;
}
::v-deep ul.el-upload-list.el-upload-list--text {
  width: 300px !important;
}
</style>
