<template>
  <div class="default-table">
    <el-table ref="editTable" :data="tableData" v-loading="tableOptions.loading" style="width: 100%" border>
      <!-- 序号 -->
      <template v-if="tableOptions.sequence">
        <el-table-column label="序号" type="index" width="60" align="center">
          <template slot-scope="scope">
            <span>{{ (pages - 1) * lines + scope.$index + 1 }}</span>
          </template>
        </el-table-column>
      </template>
      <!-- 内容字段 -->
      <template v-for="item in tableColumn">
        <el-table-column
          :prop="item.prop"
          :label="item.label"
          :width="item.width"
          :min-width="item.minWidth * 10"
          :align="item.align"
          :sortable="item.sortable ? 'custom' : false"
          :key="item.prop"
        >
          <template slot-scope="scope">
            <div
              :title="scope.row[item.prop]"
              :class="[item.elli ? '' : 'elli', item.prop == 'paraphrase' && scope.row['type'] == 0 ? 'color' : '']"
            >
              {{ scope.row[item.prop] ? scope.row[item.prop] : '-' }}
            </div>
          </template>
        </el-table-column>
      </template>
    </el-table>

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
export default {
  name: 'edit-table',
  components: {},
  props: {
    tableData: {
      type: Array,
      default() {
        return []
      }
    },

    tableColumn: {
      type: Array,
      default() {
        return [
          {
            prop: 'name',
            label: '权限名称',
            align: 'center',
            minWidth: '20'
          },
          {
            prop: 'paraphrase',
            label: '权限释义',
            align: 'center',
            minWidth: '10'
          }
        ]
      }
    },

    tableOptions: {
      type: Object,
      default() {
        return {
          sequence: false
        }
      }
    },
    pages: {
      type: Number,
      default: 0
    },
    lines: {
      type: Number,
      default: 0
    },
    total: {
      type: Number,
      default: 0
    },

    pageLayout: {
      type: String,
      default: 'total,sizes,prev, pager, next'
    }
  },
  data: () => {
    return {
      linesArr: [10, 20, 50, 100, 150, 200, 300, 400, 500, 700, 1000]
    }
  },
  methods: {
    changePage(page) {
      this.$emit('change-page', page)
    },
    changeSize(size) {
      this.$emit('change-size', size)
    }
  },
  computed: {}
}
</script>

<style lang="scss" scoped>
.elli {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.color {
  color: #5350d7;
}
</style>
