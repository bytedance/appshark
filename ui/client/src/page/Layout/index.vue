<template>
  <el-form label-width="auto">
    <ul class="main_box">
      <li class="left_box">
        <!-- 任务信息 -->
        <el-card shadow="never" class="default-card margin-top-14" v-loading="assignmentLoading">
          <div slot="header">任务信息</div>
          <el-form-item label="任务名称:">
            <div class="spanView">{{ assignment.assignmentName || '-' }}</div>
          </el-form-item>
          <el-form-item label="任务描述:">
            <ellipsis :textDetails="assignment.assignmentDescription || '-'"></ellipsis>
          </el-form-item>
          <el-form-item label="App文件:">
            <text-upload
              :disabled="true"
              :defaultFileList="[assignment.appAttach] || []"
              v-if="assignment.appAttach"
            ></text-upload>
            <div class="spanView" v-else>-</div>
          </el-form-item>
          <el-form-item label="已选规则:">
            <div class="spanView blueColor">
              <span v-for="(name, index) in (assignment.rules || '').split(',')" @click="jumpTo(name)"
                >{{ name }}{{ index == (assignment.rules || '').split(',').length - 1 ? '' : '、 ' }}</span
              >
            </div>
          </el-form-item>
          <el-form-item label="最大分析点:">
            <div class="spanView">{{ assignment.largestAnalysis || '-' }}秒</div>
          </el-form-item>
          <el-form-item label="开始扫描时间:">
            <div class="spanView">{{ assignment.scanTime || '-' }}</div>
          </el-form-item>
        </el-card>
        <!-- App基本信息 -->
        <el-card shadow="never" class="default-card margin-top-14 left_content" v-loading="assignmentLoading">
          <div slot="header">App基本信息</div>
          <el-form-item label="App名称:">
            <div class="spanView">{{ appSharkAppInfo.appName || '-' }}</div>
          </el-form-item>
          <el-form-item label="包 名:">
            <div class="spanView">{{ appSharkAppInfo.packageName || '-' }}</div>
          </el-form-item>
          <el-form-item label="min_sdk:">
            <div class="spanView">{{ appSharkAppInfo.minSdk || '-' }}</div>
          </el-form-item>
          <el-form-item label="target_sdk:">
            <div class="spanView">{{ appSharkAppInfo.targetSdk || '-' }}</div>
          </el-form-item>
          <el-form-item label="版 本:">
            <div class="spanView">{{ appSharkAppInfo.versionName || '-' }}</div></el-form-item
          >
        </el-card>
        <!-- App权限清单 -->
        <el-card shadow="never" class="default-card margin-top-14">
          <div slot="header">App权限清单</div>
          <appTable
            :tableData="tableData"
            :tableOptions="tableOptions"
            :pages="pages"
            :lines="lines"
            :total="total"
            @change-page="changePage"
            @change-size="changeSize"
          ></appTable>
        </el-card>
      </li>
      <li class="right_box">
        <el-card shadow="never" class="default-card margin-top-14" style="height: calc(100% - 13px)">
          <div slot="header">任务信息</div>
          <ul id="btnWrapper">
            <li :class="['btn', active_btn == 0 ? 'active_btn' : '']" @click="handleClick(0)">查看合规检测结果</li>
            <li :class="['btn', active_btn == 1 ? 'active_btn' : '']" @click="handleClick(1)">查看漏洞检测结果</li>
          </ul>
          <component :is="componentsArr[active_btn]"></component>
        </el-card>
      </li>
    </ul>
    <div class="margin-top-20 text-center">
      <el-button type="default" @click="goback" size="small">返 回</el-button>
      <el-button type="primary" @click="ecportReport" size="small">导出报告</el-button>
    </div>
  </el-form>
</template>

<script>
import ellipsis from './components/ellipsis'
import appTable from './components/table'
import leftList from './components/leftList'
import rightList from './components/rightList'
import textUpload from './../../components/text-upload'
import { binaryDownload } from '@/utils/download' // 二进制流下载方法
import { assignmentDetail, permissionList, exportScanReport } from '@/apis/modules/detailServe'
export default {
  components: { ellipsis, appTable, leftList, rightList, textUpload },
  data() {
    return {
      componentsArr: [leftList, rightList],
      tableData: [],
      tableOptions: {
        sequence: true,
        loading: false
      },
      pages: 1,
      lines: 10,
      total: 0,
      tips: '',
      active_btn: 0,
      activeName: 'first',
      assignmentLoading: false,
      assignment: {}, // 任务基本信息
      appSharkAppInfo: {} // App基本信息
    }
  },
  methods: {
    goback() {
      this.$router.go(-1)
    },
    jumpTo(name) {
      window.open(`http://81.69.7.178:8080/root/appshark/config/rules/${name}`, '_blank')
    },
    handleClick(num) {
      this.active_btn = num
    },
    changePage(page) {
      this.pages = page
      this.permissionListInit()
    },

    changeSize(size) {
      this.lines = size
      this.permissionListInit()
    },
    // 任务基本信息
    assignmentInit(id) {
      this.assignmentLoading = true
      assignmentDetail(
        id,
        (data) => {
          this.assignmentLoading = false
          if (data.code == '200') {
            this.assignment = data.data
            this.appSharkAppInfo = data.data.appSharkAppInfo || {}
          } else {
            this.$message.error(data.message)
          }
        },
        () => {
          this.assignmentLoading = false
        }
      )
    },
    // App基本信息
    permissionListInit() {
      this.tableOptions.loading = true
      permissionList(
        { assessmentId: this.$route.query.id, page: this.pages, rows: this.lines },
        (data) => {
          this.tableOptions.loading = false
          if (data.code == '200') {
            this.tableData = data.data.list
            this.total = data.data.total
          }
        },
        () => {
          this.tableOptions.loading = false
        }
      )
    },
    // 导出报告
    ecportReport() {
      this.tips = this.$message({
        showClose: false,
        message: `正在生成文件`,
        duration: 0
      })
      exportScanReport(
        this.$route.query.id,
        (data) => {
          if (data.code == '200') {
            this.handleDown(data)
          } else {
            this.$message.error(data.message)
          }
        },
        () => {
          this.tips.close()
        }
      )
    },
    // 下载事件
    handleDown({ data }) {
      this.$api.downLoadFileByName(
        {
          fileName: data
        },
        (res) => {
          this.tips.close()
          if (res.code == '3002') {
            this.$message.error(res.message)
          } else {
            binaryDownload(res.data, { name: data })
          }
        },
        () => {
          this.tips.close()
        }
      )
    },
    init(id) {
      this.assignmentInit(id)
      this.permissionListInit()
    }
  },
  created() {
    this.init(this.$route.query.id)
  },
  mounted() {
    let wrapper = document.getElementById('btnWrapper')
    wrapper.style.setProperty('--groove-left', '0px')
    let btns = document.getElementsByClassName('btn')
    for (let i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function (e) {
        // ThemeChange(i === 1);
        resetBtn(btns)
        wrapper.style.setProperty('--groove-left', `calc(0px + ${i * 50}%)`)
        wrapper.style.setProperty('--wraper-origin', `${i === 0 ? '75% top' : '25% top'}`)
        wrapper.style.setProperty('--wraper-rotate', `${i === 0 ? -8 : 8}deg`)
        wrapper.className = 'rotateWrap'
        setTimeout(() => {
          btns[i].className = 'btn active_btn'
        }, 100)
        setTimeout(() => {
          wrapper.className = ''
        }, 150)
      })
    }
    // 重置按钮类名
    function resetBtn(btns) {
      for (let i = 0; i < btns.length; i++) {
        setTimeout(() => {
          btns[i].className = 'btn'
        }, 100)
      }
    }
  }
}
</script>
<style lang='scss' scoped>
.main_box {
  width: 100%;
  background: #eaedf7;
  box-shadow: 1px 1px 4px 0 rgba(72, 99, 129, 0.2);
  border-radius: 0 8px 8px 8px;
  position: relative;
  overflow: auto;
  ::v-deep .el-form-item {
    margin-bottom: 0px;
  }
  .float_left {
    float: left;
    width: 50%;
  }

  .left_box {
    width: 25%;
    height: 100%;
    margin-left: 14px;
    padding-bottom: 20px;
    float: left;
  }
  .right_box {
    width: calc(75% - 42px);
    margin: 0 14px;
    float: left;
    padding-bottom: 20px;
    position: absolute;
    right: 0;
    top: 0;
    height: 100%;
    ::v-deep .el-card__body {
      height: calc(100% - 50px);
    }
    #top_btn {
      li {
        float: left;
        text-align: center;
        height: 35px;
        line-height: 35px;
        width: 140px;
        cursor: pointer;
      }
    }
  }
}
::v-deep .el-pagination {
  display: flex;
  justify-content: flex-end;
}
.main_box::after {
  content: '';
  display: block;
  clear: both;
}
.elli {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
#btnWrapper {
  position: relative;
  width: 280px;
  height: 35px;
  overflow: hidden;
  transform-origin: var(--wraper-origin);
  transition: transform 0.4s cubic-bezier(0, 0, 0.48, 1), box-shadow 0.4s linear, background-color 0.4s linear;
}

.rotateWrap {
  transform: rotateY(var(--wraper-rotate));
}

#btnWrapper::before {
  content: '';
  position: absolute;
  left: var(--groove-left);
  top: 0;
  width: 140px;
  height: 100%;
  background: #1890ff;
  transition: left 0.6s cubic-bezier(0.82, 0.12, 0.18, 0.88), box-shadow 0.3s linear;
}

.btn {
  float: left;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 50%;
  height: 100%;
  padding: inherit;
  transition: color 0.4s linear;
  animation: txtOutScale 0.6s linear;
  font-size: 14px;
  cursor: pointer;
}

.active_btn {
  color: #fff;
  transform: scale(1);
  animation: txtEnterScale 0.4s linear;
}

@keyframes txtEnterScale {
  0% {
    transform: scale(1);
  }

  100% {
    transform: scale(1);
  }
}

@keyframes txtOutScale {
  0% {
    transform: scale(1);
  }

  100% {
    transform: scale(1);
  }
}
.blueColor {
  cursor: pointer;
  color: #02a7f0;
}
::v-deep .left_content {
  .el-form-item__label {
    text-align: left;
    padding-left: 20px;
  }
}
</style>
