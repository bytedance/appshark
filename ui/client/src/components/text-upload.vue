<template>
  <div :class="{ 'hidden-upload-card': disabled }" ref="inputwrap">
    <el-upload
      :multiple="multiple"
      name="__files__"
      action
      ref="upload"
      :accept="accept"
      :file-list="myFileList"
      :on-change="handleChange"
      :on-preview="handlePictureCardPreview"
      :on-remove="appRemove"
      :disabled="disabled || unclick"
      :http-request="submitEnclosure"
      :before-upload="beforeAvatarUpload"
    >
      <div class="btn-group" v-show="!disabled">
        <template v-if="showBtn">
          <el-button slot="trigger" plain size="mini" :disabled="unclick" type="primary">选取文件</el-button>
          <slot name="tip" class="el-upload__tip" v-if="myFileList.length == 0"></slot>
        </template>
        <template v-if="showPicture && myFileList.length == 0">
          <div class="picture">
            <i slot="default" class="el-icon-plus"></i>
            <slot name="tip" class="el-upload__tip" v-if="myFileList.length == 0"></slot>
          </div>
        </template>
      </div>
    </el-upload>
  </div>
</template>

<script>
import {
  fileUpload, //   上传
  fileDownload // 下载
} from '@/apis/upload/uploadServe'
import { binaryDownload } from '@/utils/download' // 二进制流下载方法
import { fileNameValide } from '@/utils/validate.js'
export default {
  name: 'gq-upload',
  components: {},
  props: {
    showBtn: {
      type: Boolean,
      default: true
    },
    showPicture: {
      type: Boolean,
      default: false
    },
    defaultFileList: {
      type: Array,
      default() {
        return []
      }
    },
    maxImg: {
      type: Number,
      default: 1
    },
    disabled: {
      type: Boolean,
      default: false
    },
    accept: {
      type: String,
      // default: '.json, .txt, .doc, .docx, .wps, .xlsx, .xlsm, .xltx, .xltm, .pdf, .zip, .rar'
      default: '.zip,.doc,.docx,.xls,.xlsx,.xlsm,.xltx,.xltm,.pdf'
    },
    size: {
      type: Number,
      default: 0
    },
    multiple: {
      type: Boolean,
      default: false
    }
  },
  computed: {
    checkFile() {
      return function (file) {
        let strArr = this.accept.split(',')
        let fileNameArr = file.name.split('.')
        // let lastName = '.' + file.name.split('.')[1]
        let lastName = '.' + fileNameArr[fileNameArr.length - 1]
        let result = strArr.includes(lastName)
        return result
      }
    }
  },
  data() {
    return {
      unclick: false, // 禁止点击
      dialogImageUrl: '',
      dialogVisible: false,
      myFileList: [], // 回显列表
      myTitleObj: '' // 上传提示
    }
  },
  methods: {
    // 自定义上传
    submitEnclosure(file, fileList) {
      const myFormData = new FormData()
      // myFormData.set('file', file.file)
      myFormData.append('file', file.file)
      this.myFileList = this.$refs.upload.uploadFiles
      let messageInfo = this.$message({
        showClose: false,
        message: `${file.file.name}文件上传中...`,
        duration: 0
      })
      fileUpload(
        myFormData,
        this,
        (data) => {
          messageInfo.close()

          // this.myTitleObj.close()
          if (data.code == '200') {
            this.$message.success('上传成功！')
            //上传成功 时 记录
            const newName = data.data.fileNameOld
            this.myFileList.forEach((item) => {
              if (item.uid === file.file.uid) {
                item.fileId = data.data.fileId
                item.fileNameNew = data.data.fileNameNew
              }
            })
          } else {
            //上传失败 时去掉失败项
            this.$message.error(data.message)
            this.myFileList.forEach((i, index) => {
              if (i.uid === file.file.uid) {
                this.myFileList.splice(index, 1)
              }
            })
          }
          this.emitList()
        },
        (err) => {
          messageInfo.close()

          this.$message.error('文件上传失败!')
          this.myFileList.forEach((i, index) => {
            if (i.uid === file.file.uid) {
              this.myFileList.splice(index, 1)
            }
          })
        }
      )
    },
    emitList(fileId) {
      this.unclick = false
      this.$emit('update:successFileList', this.myFileList)
    },

    // 上传状态改变  替换
    handleChange(file, fileList) {
      if (fileList.length > this.maxImg) {
        fileList.splice(0, 1)
      }
    },
    // 本地删除事件
    appRemove(file, fileList) {
      if (this.myFileList.length) {
        this.myFileList.forEach((i, index) => {
          if (i.fileId === file.fileId) {
            this.myFileList.splice(index, 1)
          }
        })
        this.emitList()
      } else {
        this.$emit('update:successFileList', [])
      }
    },
    // 上传前的过滤判断
    beforeAvatarUpload(file) {
      if (this.checkFile(file)) {
        if (fileNameValide(file.name)) {
          if (this.myFileList.length == 20) {
            this.$message.error('最多上传20条')
            return false
          }
          if (file.name.length > 128) {
            this.$message.error('文件名最长不超过128个字')
            return
          }

          this.unclick = true
          this.$emit('file-before')
          // const isImg = (
          //   file.type === 'application/json' ||
          //   file.type === 'application/pdf' ||
          //   file.type === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
          //   file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
          // );
          // const isLt100M = file.size / 1024 / 1024 < 100;

          // if (!isImg) {
          //   this.$message.error('上传图片格式不正确!');
          // }
          // if (!isLt100M) {
          //   this.$message.error('上传图片大小不能超过100MB!');
          // }
          // return isLt100M;

          if (this.size > 0) {
            if (file.size > this.size * 1024 * 1024) {
              this.$message.error('上传文件大小不能超过' + this.size + 'MB!')
              this.unclick = false
              return false
            }
          }
          // 进度条
          // this.myTitleObj = this.$message({
          //   showClose: false,
          //   message: `${file.name}文件上传中...`,
          //   duration: 0
          // })
          return true
        } else {
          this.$message.error('文件名只能包含[汉字、数字、字母、下划线、（）-]')
          this.unclick = false
          return false
        }
      } else {
        this.$message.error('您选择的文件格式不正确')
        this.unclick = false
        return false
      }
      // strArr.forEach(item=>{
      //   result = file.name.lastIndexOf(item)
      // })
    },
    // 下载事件
    handlePictureCardPreview(file) {
      if (file.fileNameNew) {
        this.$api.downLoadFileByName(
          {
            fileName: file.fileNameNew
          },
          (res) => {
            binaryDownload(res.data, file)
            this.$emit('update:feedback')
          }
        )
      }
    }
  },
  destroyed() {
    if (this.myTitleObj) {
      this.myTitleObj.close()
    }
  },
  mounted() {
    this.myFileList = this.$common.deepClone(this.defaultFileList)
    if (this.defaultFileList.length > 0) {
      this.myFileList = this.myFileList.map((item) => {
        item.name = item.fileName
        return item
      })
    }
  },
  watch: {
    defaultFileList: {
      handler(val) {
        if (val.length >= 0) {
          // console.log('收到文件列表', val)
          this.myFileList = this.$common.deepClone(this.defaultFileList)
          this.myFileList = this.$common.deepClone(this.myFileList)
          this.myFileList = val.map((item) => {
            if (item.fileName) {
              item.name = item.fileName
            }

            return item
          })
        }
      },
      deep: true
    }
  }
}
</script>

<style lang='scss' scoped>
.width-max {
  width: 100%;
}

.btn-group {
  width: 100%;
  text-align: left;
}
.el-icon-plus {
  font-size: 30px;
  margin: 25px 0 10px 0;
}
.picture {
  width: 250px;
  height: 120px;
  text-align: center;
  border-radius: 5px;
  border: 1px solid #eee;
}
.voucherUpload {
  ::v-deep .el-upload-list {
    float: left !important;
    margin-top: -6px !important;
  }
}
</style>
