<template>
  <div class="box-container default-box">
    <slot-box class="b-mb-10" :labelWidth="labelWidth" :showSpan="true">
      <div slot="left_header" class="search_left">
        <el-form-item label="任务名称:" class="b-dib">
          <el-input
            v-model.trim="getListParams.assignmentName"
            @click.native.stop
            placeholder="请输入任务名称"
            clearable
            maxlength="20"
          ></el-input>
        </el-form-item>
        <el-form-item label="任务状态:" class="b-dib">
          <el-select v-model="getListParams.assignmentProcessStatus" filterable placeholder="请选择" clearable>
            <el-option
              v-for="(item, index) in statusList"
              :label="item.label"
              :value="item.value"
              :key="index"
            ></el-option>
          </el-select>
        </el-form-item>
      </div>
      <div slot="right_header" class="search_right">
        <el-button type="primary" size="small" @click="getListData">搜 索</el-button>
        <el-button type="default" size="small" @click="reset">重 置</el-button>
      </div>
      <div slot="footer" class="search_left">
        <el-form-item label="创建时间:" class="b-dib">
          <el-date-picker
            v-model="times"
            type="daterange"
            range-separator="-"
            start-placeholder="开始日期"
            end-placeholder="结束日期"
            value-format="yyyy-MM-dd HH:mm:ss"
            format="yyyy-MM-dd"
            :default-time="['00:00:00', '23:59:59']"
            :picker-options="pickerOptions"
          >
          </el-date-picker>
        </el-form-item>
      </div>
    </slot-box>
    <div class="clearfix b-mt-20">
      <div class="float-l">
        <el-button type="primary" size="small" @click="add"> 创建任务 </el-button>
      </div>
      <div class="float-r">
        <el-button size="small" @click="importVisible = true"> 导入规则 </el-button>
        <el-button size="small" type="danger" style="margin-left: 30px" :disabled="!multiple.length" @click="batchDel">
          批量删除
        </el-button>
      </div>
    </div>
    <div style="position: relative" class="b-pb-20 el-card b-mt-10">
      <el-table
        ref="editTable"
        :data="listData"
        style="width: 100%"
        stripe
        highlight-current-row
        class="default-table"
        border
        @selection-change="handleSelectionChange"
        @sort-change="changeTableSort"
      >
        <el-table-column type="selection" align="center" width="55" key="1"></el-table-column>
        <el-table-column label="序号" fixed="left" :[serialField]="80" align="center" key="2">
          <template slot-scope="scope">
            <span>{{ (getListParams.page - 1) * getListParams.rows + scope.$index + 1 }}</span>
          </template>
        </el-table-column>
        <el-table-column
          label="任务编号"
          prop="guid"
          align="center"
          minWidth="160px"
          key="3"
          v-if="tableHandleList[0].ispass"
          :show-overflow-tooltip="true"
        >
        </el-table-column>
        <el-table-column
          label="任务名称"
          prop="assignmentName"
          align="center"
          minWidth="160px"
          key="4"
          v-if="tableHandleList[1].ispass"
        >
        </el-table-column>
        <el-table-column label="APP文件" align="center" minWidth="160px" key="5" v-if="tableHandleList[2].ispass">
          <template slot-scope="{ row }">
            <template v-if="row.appAttach">
              <span @click="downLoad(row.appAttach)" style="color: #02a7f0" class="pointer">
                {{ row.appAttach.fileName }}
              </span>
            </template>
          </template>
        </el-table-column>
        <el-table-column
          label="规则"
          prop="rules"
          align="center"
          minWidth="200px"
          key="6"
          v-if="tableHandleList[3].ispass"
        >
        </el-table-column>
        <el-table-column
          label="任务状态"
          align="center"
          width="160px"
          key="7"
          v-if="tableHandleList[4].ispass"
          sortable="custom"
          prop="processStatus"
        >
          <template slot-scope="{ row }">
            <span :style="{ color: formateStatus(row.processStatus) }">
              {{ row.processStatus | formatProcessStatus }}
            </span>
          </template>
        </el-table-column>
        <el-table-column
          label="开始扫描时间"
          prop="scanTime"
          align="center"
          width="160px"
          key="8"
          v-if="tableHandleList[5].ispass"
          sortable="custom"
        >
        </el-table-column>
        <el-table-column
          label="创建时间"
          prop="createdAt"
          align="center"
          width="160px"
          key="9"
          v-if="tableHandleList[6].ispass"
          sortable="custom"
        >
        </el-table-column>
        <el-table-column label="操作" align="center" width="200px" fixed="right" key="10">
          <template slot-scope="{ row }">
            <span
              class="pointer"
              style="color: #02a7f0"
              @click="lookDetail(row)"
              v-if="row.processStatus === 'FINISHED'"
            >
              查看检测结果
            </span>
            <span v-else>--</span>
          </template>
        </el-table-column>
      </el-table>
      <el-popover placement="bottom" width="200" trigger="hover" class="checkbox_point">
        <el-checkbox-group v-model="check" class="checkbox_group">
          <div class="group_clomn">
            <el-checkbox
              class="group_item"
              v-for="item in tableHandleList"
              :key="item.label"
              :label="item.label"
            ></el-checkbox>
          </div>
        </el-checkbox-group>
        <span slot="reference" class="el-icon-caret-bottom" style="cursor: pointer"></span>
      </el-popover>
      <systemPagination
        class="b-mt-10 f-tar"
        :total="listTotal"
        :page-size="getListParams.rows"
        :current-page="getListParams.page"
        @changepages="getListData"
      >
      </systemPagination>
    </div>

    <!-- 导入规则 START -->
    <el-dialog
      title="导入规则"
      center
      :visible.sync="importVisible"
      width="30%"
      :before-close="closeDialog"
      :modal="false"
    >
      <el-form label-width="100px">
        <el-form-item label="规则文件:" ref="file">
          <el-upload
            ref="uploadFile"
            action=""
            :http-request="uploadRequest"
            :file-list="fileList"
            :limit="1"
            :on-exceed="fileExceed"
            accept=".json"
          >
            <el-button size="small" type="default">选取文件</el-button>
            <span slot="tip" class="el-upload__tip grey b-ml-20">仅支持上传json格式文件</span>
          </el-upload>
        </el-form-item>
      </el-form>
      <div slot="footer">
        <el-button @click="closeDialog" size="small">取 消</el-button>
        <el-button type="primary" @click="handleSubmit" size="small">确 认</el-button>
      </div>
    </el-dialog>
    <!-- 导入规则 END -->
  </div>
</template>

<script>
import slotBox from '@/components/serchSlot'
import systemPagination from '@/components/system_pagination.vue'
import { binaryDownload } from '@/utils/download'
import { mapGetters } from 'vuex'
import { queryByPage, uploadRules, batchRemove } from '@/apis/modules/login'
export default {
  name: 'list',
  components: { slotBox, systemPagination },
  data() {
    return {
      labelWidth: '140px',
      // 获取列表入参
      getListParams: {
        assignmentName: '', // 任务名称
        assignmentProcessStatus: '', // 任务状态
        startTime: '',
        endTime: '',
        page: 1,
        rows: 10
      },
      times: '',
      statusList: [
        { value: 'WAITING', label: '未开始' },
        { value: 'PROCESSING', label: '进行中' },
        { value: 'FINISHED', label: '检测成功' },
        { value: 'ERROR', label: '检测失败' }
      ],
      listData: [],
      listTotal: 0,
      multiple: [],
      // 可操作的列
      tableHandleList: [
        { label: '任务编号', ispass: false },
        { label: '任务名称', ispass: true },
        { label: 'APP文件', ispass: true },
        { label: '规则', ispass: true },
        { label: '任务状态', ispass: true },
        { label: '开始扫描时间', ispass: false },
        { label: '创建时间', ispass: false }
      ],
      selectLine: ['任务编号', '任务名称', 'APP文件', '规则', '任务状态', '开始扫描时间', '创建时间'],
      check: ['任务名称', 'APP文件', '规则', '任务状态'],
      circleColor: [
        {
          type: 'WAITING',
          color: '#7F7F7F'
        },
        {
          type: 'PROCESSING',
          color: '#70B603'
        },
        {
          type: 'ERROR',
          color: '#D9001B'
        },
        {
          type: 'FINISHED',
          color: '#02A7F0'
        }
      ],
      importVisible: false, // 导入规则弹框
      fileList: [],
      formData: '',
      // 设置选择今天以及今天以前的日期
      pickerOptions: {
        disabledDate(time) {
          let now = new Date()
          let year = now.getFullYear()
          let month = now.getMonth() + 1
          let day = now.getDate() + 1
          let times = year + '/' + month + '/' + day + ' 00:00:00'
          let limitTime = new Date(times).getTime()
          return time.getTime() > limitTime || time.getTime() === limitTime
        }
      }
    }
  },
  computed: {
    ...mapGetters(['playManageDefaultTable']),
    serialField() {
      return this.check.length ? 'width' : 'min-width'
    }
  },
  created() {
    if (this.playManageDefaultTable.length) {
      this.tableHandleList = [...this.playManageDefaultTable]
      this.check = []
      this.tableHandleList.forEach((item) => {
        if (item.ispass) {
          this.check.push(item.label)
        }
      })
    } else {
      this.$store.commit('SET_COLUMNS', { key: 'playManageDefaultTable', data: this.tableHandleList })
    }
  },
  mounted() {
    this.getListData() // 获取列表数据
  },
  methods: {
    // 获取列表数据
    getListData(pages) {
      let loading = this.$loading({ background: 'rgba(255, 255, 255, 0.9)' })
      // 设置页数
      if (pages && pages.pageNum) {
        this.getListParams.page = pages.pageNum
      } else {
        this.getListParams.page = 1
      }
      // 设置每页个数
      if (pages && pages.pageSize) {
        this.getListParams.rows = pages.pageSize
      }
      // 处理创建时间
      if (this.times && this.times.length === 2) {
        this.getListParams.startTime = this.times[0]
        this.getListParams.endTime = this.times[1]
      } else {
        this.getListParams.startTime = ''
        this.getListParams.endTime = ''
      }
      queryByPage(this.getListParams, (data) => {
        const { code, message } = data
        if (code !== '200') {
          this.$message.error(message)
          loading.close()
          return
        }
        this.listData = data.data.list || []
        this.listTotal = data.data.total
        loading.close()
      }),
        () => {
          loading.close()
        }
    },
    // 重置
    reset() {
      Object.assign(this.$data.getListParams, this.$options.data().getListParams)
      this.times = '' // 创建时间
      this.getListData() // 获取列表数据
    },
    handleSelectionChange(current) {
      this.multiple = current
    },
    // 下载APP文件
    downLoad(val) {
      let messageInfo = this.$message({
        showClose: false,
        message: `下载中...`,
        duration: 0
      })
      this.$api.downLoadFileByName(
        {
          fileName: val.fileName
        },
        (res) => {
          if (res.status !== 200) {
            this.$message.error('下载失败')
            messageInfo.close()
            return
          }
          binaryDownload(res.data, { name: val.fileName })
          messageInfo.close()
        }
      )
    },
    // 任务状态颜色
    formateStatus(planStatus) {
      let obj = this.circleColor.find((item) => item.type === planStatus)
      return obj ? obj.color : ''
    },
    // 批量删除
    batchDel() {
      this.$confirm('确认删除已选内容吗?', '批量删除', {
        confirmButtonText: '确定',
        cancelButtonText: '取消'
      })
        .then(() => {
          let ids = this.multiple.map((item) => item.id)
          batchRemove({ ids }, (data) => {
            const { code, message } = data
            if (code !== '200') {
              this.$message.error(message)
              return
            }
            this.$message({ type: 'success', message: '删除成功!' })
            this.getListData() // 获取列表数据
          })
        })
        .catch(() => {})
    },
    // 排序
    changeTableSort(column) {
      let loading = this.$loading({ background: 'rgba(255, 255, 255, 0.9)' })
      const typeList = [
        {
          prop: 'processStatus',
          descending: 'processStatus desc',
          ascending: 'processStatus asc'
        },
        { prop: 'scanTime', descending: 'scanTime desc', ascending: 'scanTime asc' },
        { prop: 'createdAt', descending: 'createdAt desc', ascending: 'createdAt asc' }
      ]
      if (!column.order) {
        this.getListParams.orderBy = ''
      } else {
        this.getListParams.orderBy = typeList.find((item) => item.prop === column.prop)[column.order]
      }
      // 处理时间
      if (this.times && this.times.length === 2) {
        this.getListParams.startTime = this.times[0]
        this.getListParams.endTime = this.times[1]
      } else {
        this.getListParams.startTime = ''
        this.getListParams.endTime = ''
      }
      queryByPage(this.getListParams, (data) => {
        const { code, message } = data
        if (code !== '200') {
          this.$message.error(message)
          loading.close()
          return
        }
        this.listData = data.data.list || []
        this.listTotal = data.data.total
        loading.close()
      })
    },
    // 创建任务
    add() {
      this.$router.push({ name: 'add' })
    },
    // 上传文件超出上传个数
    fileExceed() {
      this.$message.error('一次仅支持上传一个文件')
    },
    // 上传json文件
    uploadRequest(res) {
      const file = res.file
      var testmsg = file.name.substring(file.name.lastIndexOf('.') + 1)
      if (testmsg !== 'json') {
        this.$message({ message: '上传失败，仅支持上传.json格式的文件', type: 'error' })
        let uid = file.uid
        let idx = this.$refs.uploadFile.uploadFiles.findIndex((item) => item.uid === uid)
        this.$refs.uploadFile.uploadFiles.splice(idx, 1)
        return
      }
      this.formData = new FormData()
      this.formData.append('file', file)
    },
    // 弹框-关闭
    closeDialog() {
      this.importVisible = false
      this.fileList = []
      this.formData = ''
    },
    // 弹框-确认
    handleSubmit() {
      if (!this.formData) {
        this.$message.error('请上传文件')
        return
      }
      let loading = this.$loading({ background: 'rgba(255, 255, 255, 0.9)' })
      uploadRules(this.formData, (res) => {
        const { code, message } = res
        if (code !== '200') {
          this.$message.error(message)
          loading.close()
          return
        }
        this.$message({ type: 'success', message: '上传成功!' })
        this.closeDialog() // 弹框-关闭
        loading.close()
        this.getListData() // 获取列表数据
      })
    },
    lookDetail(row) {
      this.$router.push({
        name: 'Layout',
        query: {
          id: row.id
        }
      })
    }
  },
  watch: {
    check(newVal) {
      if (newVal) {
        var arr = this.selectLine.filter((i) => newVal.indexOf(i) < 0) // 未选中
        this.tableHandleList.map((i) => {
          if (arr.indexOf(i.label) !== -1) {
            i.ispass = false
          } else {
            i.ispass = true
          }
        })
        this.$nextTick(() => {
          // this.$refs.editTable.doLayout()
        })
      }
    }
  }
}
</script>

<style lang="scss" scoped>
.search_left {
  width: calc(100% - 260px);
  .el-form-item {
    width: 40%;
    margin-right: 3%;
    margin-bottom: 0;
    .el-select {
      width: 100%;
    }
  }
}
.search_right {
  min-width: 200px;
  float: right;
}
.checkbox_group {
  display: flex;
  justify-content: center;
  .group_clomn {
    display: flex;
    flex-direction: column;
    margin: 0 20px;
    .group_item {
      margin: 4px 0;
    }
  }
}
.checkbox_point {
  position: absolute;
  z-index: 10;
  top: 18px;
  right: 59px;
  font-size: 15px;
}
.box-container {
  border-radius: 0 8px 8px 8px;
  padding: 14px;
  background-color: #eaedf7;
  min-height: calc(100vh - 140px);
}
</style>
