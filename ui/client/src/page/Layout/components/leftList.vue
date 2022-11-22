<template>
  <div style="height: calc(100% - 35px)">
    <search @handleSearch="init" />
    <ul class="top_ul">
      <li>合规检测结果汇总</li>
      <li @click="handleClick">点击查看全部行为数据</li>
      <li>以下检测结果为自动化输出，相关行为合规性请根据产品功能、信息采集的目的、方式、范围等综合判断</li>
    </ul>
    <ul class="title_ul" v-loading="titleloading">
      <li v-for="(item, index) in titleList" :key="index" class="title_btn" @click="titleClick(item, index)">
        <span :style="{ background: colorArr[index] }"></span>
        <span
          :title="item.name"
          :class="['elli', active_index == index ? 'active_index' : '']"
          :style="{ color: active_index == index ? colorArr[active_index] : '' }"
          >{{ item.name }}</span
        >
        <span>{{ item.value }}</span>
      </li>
    </ul>
    <div v-loading="dataloading" style="height: calc(100% - 240px)">
      <div class="right_scroll" v-if="dataList.length">
        <ul class="ul_box" v-for="(item, index) in dataList" :key="index">
          <li>
            <el-form-item label="位 置:" label-width="80px">
              <div class="spanView">
                {{ item.position || '-' }}
              </div>
            </el-form-item>
            <el-form-item label="堆 栈:" label-width="80px">
              <div class="spanView break">
                {{ sortTargets(item.targets) }}
              </div>
            </el-form-item>
          </li>
          <li :style="{ color: item.color }" :title="item.name" class="elli">{{ item.name }}</li>
        </ul>
      </div>
      <el-empty description="暂无数据" v-else></el-empty>
    </div>
    <el-pagination
      style="margin: 5px; width: 100%"
      :small="true"
      v-if="total > 10"
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
import search from './search'
import { queryCamilleMap, complianceList } from '@/apis/modules/detailServe'
export default {
  name: 'leftList',
  components: { search },
  props: {},
  data() {
    return {
      linesArr: [10, 20, 50, 100, 150, 200, 300, 400, 500, 700, 1000],
      pageLayout: 'total,sizes,prev, pager, next',
      titleloading: false,
      dataloading: false,
      assessmentId: '',
      searchParams: {},
      vulnerNames: [], //选中title
      // 颜色字典
      colorArr: [
        '#0076AA',
        '#9D4607',
        '#440B8C',
        '#05641A',
        '#0B94CA',
        '#DD6107 ',
        '#6E04C1 ',
        '#14A807',
        '#0F90EE',
        '#F6610E ',
        '#6E2EF6',
        '#46C64B',
        '#04B2F6',
        '#F9A930',
        '#655AE6',
        '#71B97C'
      ],
      active_index: 0, //选中下标
      titleList: [], // 标题集合
      dataList: [], //数据集合
      total: 0,
      pages: 1,
      lines: 10
    }
  },
  methods: {
    handleClick() {
      this.vulnerNames = []
      this.active_index = 16
      this.init({})
    },
    titleClick(item, index) {
      this.vulnerNames = [item.name]
      this.active_index = index
      this.init(this.searchParams)
    },
    changePage(page) {
      this.pages = page
      this.getListData()
    },

    changeSize(size) {
      this.lines = size
      this.getListData()
    },
    // 合规检测结果标题列表
    getTitleList() {
      this.titleloading = true
      queryCamilleMap(
        this.assessmentId,
        (data) => {
          if (data.code == '200') {
            let obj = data.data || {}
            this.titleList = Object.keys(obj).map((key, index) => {
              return {
                name: key,
                value: obj[key],
                color: this.colorArr[index]
              }
            })

            if (this.titleList.length) {
              this.vulnerNames = [this.titleList[0].name]
              this.init()
            }
          } else {
            this.$message.error(data.message)
          }
          this.titleloading = false
        },
        () => {
          this.titleloading = false
        }
      )
    },
    getListData(reset) {
      reset && (this.titleList.length && (this.vulnerNames = [this.titleList[0].name]), (this.active_index = 0))
      this.dataloading = true
      let params = {
        rows: this.lines,
        page: this.pages,
        assessmentId: this.assessmentId,
        vulnerNames: this.vulnerNames,
        ...this.searchParams
      }
      complianceList(
        params,
        (data) => {
          if (data.code == '200') {
            let arr = data.data.list || []
            arr.map((item) => {
              let obj = this.titleList.find((i) => i.name == item.name)
              if (obj) {
                item.color = obj.color
              } else {
                item.color = this.colorArr[15]
              }
            })
            this.dataList = arr
            this.total = data.data.total
          } else {
            this.$message.error(data.message)
          }
          this.dataloading = false
        },
        () => {
          this.dataloading = false
        }
      )
    },
    sortTargets(arr) {
      let str = ''
      if (arr && arr.length) {
        arr.map((item) => {
          str += item + '\n'
        })
        str = str.slice(0, str.length - 1)
      } else {
        str = '-'
      }
      return str
    },
    init(searchParams, reset) {
      this.searchParams = searchParams
      this.pages = 1
      this.lines = 10
      this.getListData(reset)
    }
  },
  created() {
    this.assessmentId = this.$route.query.id
    this.getTitleList()
  },
  mounted() {}
}
</script> 

<style lang="scss"scoped>
.top_ul {
  margin: 0 10px;
  box-sizing: border-box;
  display: flex;
  li {
    float: left;
    height: 35px;
    line-height: 35px;
    padding: 0 18px 0 2px;
    font-size: 14px;
  }
  li:nth-of-type(1) {
    font-weight: bold;
  }
  li:nth-of-type(2) {
    color: #02a7f0;
    cursor: pointer;
  }
  li:nth-of-type(3) {
    color: gray;
    flex: 1;
    text-align: right;
    padding: 5px 10px;
    line-height: 25px;
    font-size: 12px;
  }
}
.title_ul {
  width: 94%;
  clear: both;
  margin: 15px 3% 0 3%;
  .title_btn {
    float: left;
    width: 20%;
    margin: 5px 2.5%;
    cursor: pointer;
    height: 25px;
    display: flex;
    align-content: center;
    justify-content: flex-start;
    > span {
      line-height: 25px;
    }
    .elli {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    span:nth-of-type(1) {
      display: inline-block;
      width: 15px;
      height: 15px;
      border-radius: 100%;
      margin-top: 5px;
    }
    span:nth-of-type(2) {
      width: calc(100% - 85px);
      padding: 0 5px;
      line-height: 25px;
      font-size: 14px;
    }
    span:nth-of-type(3) {
      width: 60px;
      line-height: 25px;
      font-size: 14px;
    }
  }
  .active_index {
    font-weight: bold;
  }
}
.top_ul::after,
.title_ul::after,
.ul_box::after {
  content: '';
  display: block;
  clear: both;
}
::v-deep .right_scroll {
  margin-top: 20px;
  overflow-y: auto;
  height: 100%;
}
.ul_box {
  width: 100%;
  border: 1px solid #eeeeee;
  padding: 5px 0 10px 0;
  margin: 10px 0;
  li {
    float: left;
  }
  li:nth-of-type(1) {
    width: calc(100% - 150px);
  }
  li:nth-of-type(2) {
    width: 150px;
    text-align: right;
    padding: 7px 10px;
    font-size: 14px;
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
</style>