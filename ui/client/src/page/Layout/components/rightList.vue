<template>
  <div style="height: calc(100% - 48px)">
    <div class="search_top">
      <el-form-item label="漏洞名称:" class="search_left">
        <el-input v-model.trim="searchParams.vulnerName" placeholder="请输入漏洞名称"></el-input>
      </el-form-item>
      <div slot="right_header" class="search_right">
        <el-button type="primary" size="small" @click="onSearch">搜 索</el-button>
        <el-button type="default" size="small" @click="resetSearch">重 置</el-button>
      </div>
    </div>

    <ul class="top_ul" v-loading="topLoding">
      <li>
        <div>
          <div style="height: 100%; width: 100%" id="compass_pie"></div>
          <span
            ><i>{{ countVulner }}</i> <br />
            漏洞 (条)</span
          >
        </div>
      </li>
      <li>
        <div v-for="(item, index) in appSharkVulnerRatioList" :key="index">
          <span :class="[fingType(item.model, 'model')]"></span>
          <span :class="[active_index == index ? fingType(item.model, 'text') : '']" @click="titleClick(item, index)">{{
            fingType(item.model, 'name')
          }}</span>
          <span>{{ item.countVulner }}条</span>
          <span>{{ item.vulnerRatio }}</span>
        </div>
      </li>
    </ul>
    <div v-loading="loading" style="height: calc(100% - 310px)">
      <div v-if="titleList.length" class="right_scroll">
        <div v-for="(item, index) in titleList" :key="index" :class="['div_box', fingType(item.model, 'divClass')]">
          <h3>漏洞基础信息</h3>
          <el-form-item label="漏洞名称:">
            <div class="spanView">
              <span :class="['ld_span', fingType(item.model, 'spanClass')]">
                {{ fingType(item.model, 'type') }}
              </span>
              {{ item.name }}
            </div>
          </el-form-item>
          <el-form-item label="漏洞类型:">
            <div class="spanView">{{ item.category }}</div>
          </el-form-item>
          <el-form-item label="漏洞描述:">
            <div class="spanView">{{ item.detail }}</div>
          </el-form-item>
          <h3>漏洞详情</h3>
          <el-form-item label="位 置:">
            <div class="spanView">{{ item.appSharkTraversalVulner ? item.appSharkTraversalVulner.position : '-' }}</div>
          </el-form-item>
          <el-form-item label="分析入口:">
            <div class="spanView">
              {{ item.appSharkTraversalVulner ? item.appSharkTraversalVulner.entryMethod : '-' }}
            </div>
          </el-form-item>
          <el-form-item label="传播起点:">
            <div class="spanView break">{{ sortTargets(item.appSharkTraversalSources, 'source') }}</div>
          </el-form-item>
          <el-form-item label="传播路径:">
            <div class="spanView break">{{ sortTargets(item.appSharkTraversalTargets, 'target') }}</div>
          </el-form-item>
          <el-form-item label="传播终点:">
            <div class="spanView break">{{ sortTargets(item.appSharkTraversalSinks, 'sink') }}</div>
          </el-form-item>
          <el-form-item label="详 情:">
            <div class="spanView blueColor" @click="jumpTo(item.appSharkTraversalVulner)">
              {{ item.appSharkTraversalVulner ? item.appSharkTraversalVulner.url : '-' }}
            </div>
          </el-form-item>
        </div>
      </div>
      <el-empty description="暂无数据" v-else></el-empty>
    </div>
    <el-pagination
      v-if="total > 10"
      style="margin: 5px; width: 100%"
      :small="true"
      :pager-count="Number(5)"
      :layout="pageLayout"
      :page-size="lines"
      :page-sizes="linesArr"
      :current-page="pages"
      :total="total"
      @prev-click="changePage"
      @next-click="changePage"
      @current-change="changePage"
      @size-change="changeSize"
    ></el-pagination>
  </div>
</template> 

<script>
import * as echarts from 'echarts'
import { statisticsType, vulnerList } from '@/apis/modules/detailServe'
export default {
  name: 'leftList',
  components: {},
  props: {},
  data() {
    return {
      linesArr: [10, 20, 50, 100, 150, 200, 300, 400, 500, 700, 1000],
      topLoding: false,
      loading: false,
      searchParams: {
        vulnerName: '',
        vulnerModel: ''
      },
      appSharkVulnerRatioList: [], // 统计图
      countVulner: 0,
      pageLayout: 'total,sizes,prev, pager, next',
      titleList: [], // 列表数据
      ruleArr: [
        // 分类字典
        {
          model: 'severity',
          text: 'severityText',
          divClass: 'severity_div',
          spanClass: 'severity_span',
          type: '严重',
          name: '严重漏洞'
        },
        {
          model: 'high',
          text: 'highText',
          divClass: 'major_div',
          spanClass: 'major_span',
          type: '高危',
          name: '高危漏洞'
        },
        {
          model: 'middle',
          text: 'middleText',
          divClass: 'general_div',
          spanClass: 'general_span',
          type: '中危',
          name: '中危漏洞'
        },
        {
          model: 'low',
          text: 'lowText',
          divClass: 'minor_div',
          spanClass: 'minor_span',
          type: '低危',
          name: '低危漏洞'
        },
        {
          model: 'other',
          text: 'otherText',
          divClass: 'other_div',
          spanClass: 'other_span',
          type: '暂无级别',
          name: '暂无级别'
        }
      ],

      active_index: 5,
      total: 100,
      pages: 1,
      lines: 10
    }
  },
  methods: {
    // 重置搜索
    resetSearch() {
      this.searchParams = {
        vulnerName: '',
        vulnerModel: ''
      }
      this.active_index = 5
      this.onSearch()
    },

    onSearch() {
      this.init()
    },
    titleClick(item, index) {
      if (this.active_index == index) {
        this.active_index = null
        this.searchParams.vulnerModel = ''
      } else {
        this.active_index = index
        this.searchParams.vulnerModel = item.model
      }

      this.onSearch()
    },
    jumpTo(obj) {
      let url = obj.url
      window.open(`http://81.69.7.178:8080${url}`, '_blank')
    },
    // 归类漏洞类型
    fingType(model, key) {
      if (model) {
        let obj = this.ruleArr.find((item) => item.model == model)
        if (obj) {
          return obj[key]
        } else {
          return this.ruleArr[5][key]
        }
      } else {
        return this.ruleArr[5][key]
      }
    },
    // 数组字符串拼接
    sortTargets(arr, key) {
      let str = ''
      if (arr && arr.length) {
        arr.map((item) => {
          str += item[key] + '\n'
        })
        str = str.slice(0, str.length - 1)
      } else {
        str = '-'
      }
      return str
    },
    getStatisticsType() {
      this.topLoding = true
      statisticsType(
        { assessmentId: this.$route.query.id },
        (data) => {
          if (data.code == '200') {
            this.appSharkVulnerRatioList = data.data.appSharkVulnerRatioList
            this.countVulner = data.data.countVulner
            this.initChart(this.appSharkVulnerRatioList)
          } else {
            this.$message.error(data.message)
          }
          this.topLoding = false
        },
        () => {
          this.topLoding = false
        }
      )
    },
    changePage(page) {
      this.pages = page
      this.getListData()
    },

    changeSize(size) {
      this.lines = size
      this.getListData()
    },
    //获取列表
    getListData() {
      this.loading = true
      let params = {
        rows: this.lines,
        page: this.pages,
        assessmentId: this.$route.query.id,
        ...this.searchParams
      }
      vulnerList(
        params,
        (data) => {
          if (data.code == '200') {
            let obj = data.data || {}
            this.pushObj(obj.list || [])
            this.total = obj.total || 0
          } else {
            this.$message.error(data.message)
            this.loading = false
          }
        },
        () => {
          this.loading = false
        }
      )
    },
    pushObj(arr) {
      let array = this.$common.deepClone(arr),
        array1 = [arr[0]]
      if (arr.length == 1) {
        this.titleList = array1
        this.loading = false
      } else if (arr.length > 1) {
        let array2 = array.splice(1, array.length - 1)
        this.titleList = array1
        setTimeout(() => {
          this.titleList = [...array1, ...array2]
          this.loading = false
        }, 1000)
      } else {
        this.titleList = arr
        this.loading = false
      }
    },
    init() {
      this.pages = 1
      this.lines = 10
      this.getListData()
    },
    initChart(data) {
      data.map((item) => {
        item.name = this.fingType(item.model, 'name')
        item.value = item.countVulner
      })
      var chartDom = document.getElementById('compass_pie')
      var myChart = echarts.init(chartDom)
      var option
      ;(option = {
        tooltip: {
          trigger: 'item'
        },
        legend: {
          show: false
        },
        color: ['#a30014', '#d9001b', '#f59a23', '#02a7f0', '#AAAAAA'],
        series: [
          {
            name: '',
            type: 'pie',
            center: ['50%', '50%'],
            radius: ['60%', '80%'],
            avoidLabelOverlap: false,
            label: {
              normal: {
                show: false,
                position: 'center'
              }
            },
            emphasis: {
              label: {
                show: false,
                fontSize: '12',
                fontWeight: 'bold'
              }
            },
            labelLine: {
              normal: {
                show: false
              }
            },
            itemStyle: {
              normal: {}
            },
            data: data
          }
        ]
      }),
        option && myChart.setOption(option)
      window.addEventListener('resize', myChart.resize)
    }
  },
  created() {
    this.getStatisticsType()
    this.init()
  }
}
</script> 

<style lang="scss" scoped>
.top_ul {
  margin: 20px 10px 10px 10px;
  li {
    float: left;
    height: 200px;
    width: 50%;
  }
  li:nth-of-type(1) {
    display: flex;
    justify-content: center;
    > div {
      width: 200px;
      height: 200px;
      margin: 0 0 0 45%;
      position: relative;
      > span {
        position: absolute;
        width: 100px;
        font-size: 15px;
        left: 50px;
        top: 77px;
        text-align: center;
        i {
          font-style: normal;
          font-size: 25px;
        }
      }
    }
  }
  li:nth-of-type(2) {
    display: flex;
    flex-direction: column;
    justify-content: center;
    > div {
      height: 35px;
      display: flex;
      justify-content: flex-start;
      align-items: center;
      .severity {
        background: #a30014;
      }
      .high {
        background: #d9001b;
      }
      .middle {
        background: #f59a23;
      }
      .low {
        background: #02a7f0;
      }
      .other {
        background: #aaaaaa;
      }
      .severityText {
        color: #a30014;
        font-weight: bold;
      }
      .highText {
        color: #d9001b;
        font-weight: bold;
      }
      .middleText {
        color: #f59a23;
        font-weight: bold;
      }
      .lowText {
        color: #02a7f0;
        font-weight: bold;
      }
      .otherText {
        color: #aaaaaa;
        font-weight: bold;
      }

      > span:nth-of-type(1) {
        width: 14px;
        height: 14px;
        border-radius: 100%;
      }
      > span:nth-of-type(2) {
        width: 100px;
        margin: 0 5px;
        cursor: pointer;
        font-size: 14px;
      }
      > span:nth-of-type(3) {
        width: 80px;
        text-align: right;
      }
      > span:nth-of-type(4) {
        width: 80px;
        text-align: center;
      }
    }
  }
}
.search_top::after,
.top_ul::after,
.div_box::after {
  content: '';
  display: block;
  clear: both;
}
.right_scroll {
  margin-top: 20px;
  overflow-y: auto;
  height: 100%;
}
.div_box {
  width: 100%;
  border: 1px solid #eeeeee;
  border-radius: 6px;
  padding: 10px 0;
  margin: 10px 0;
  > h3 {
    height: 30px;
    line-height: 35px;
    text-indent: 1em;
    font-size: 15px;
  }
  .ld_span {
    font-size: 13px;
    padding: 1px 2px;
    color: #fff;
    margin-right: 10px;
  }
  .severity_span {
    background: #a30014;
  }
  .major_span {
    background: #d9001b;
  }
  .general_span {
    background: #f59a23;
  }
  .minor_span {
    background: #02a7f0;
  }
  .other_span {
    background: #aaaaaa;
  }
}
.severity_div {
  background: #f9d7db;
}
.major_div {
  background: #ffeef0;
}
.general_div {
  background: #fff5e7;
}
.minor_div {
  background: #f3fbff;
}
.other_div {
  background: #f2f2f2;
}
// ::v-deep .el-pagination__rightwrapper {
//   float: left;
// }
.default-search::after {
  content: '';
  display: block;
  clear: both;
}
.search_top {
  margin-top: 15px;
  padding-left: 15px;
  display: flex;
  align-items: center;
  .search_left {
    width: 500px;
  }
  .search_right {
    margin: 0 20px;
  }
}
.empty {
  height: 300px;
  line-height: 300px;
  text-align: center;
  font-size: 15px;
}
.break {
  white-space: break-spaces;
}
.blueColor {
  cursor: pointer;
  color: #02a7f0;
}
</style>