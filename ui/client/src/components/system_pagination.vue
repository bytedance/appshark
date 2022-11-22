<template>
  <div>
    <el-pagination
      background
      :hide-on-single-page="false"
      :current-page="currentPage"
      :page-size="pageSize"
      @size-change="handleSizeChange"
      @current-change="handleCurrentChange"
      :page-sizes="pageSizes"
      :layout="paginationLayout"
      :total="total"
      :small="isSmall"
    >
    </el-pagination>
  </div>
</template>

<script>
export default {
  data() {
    return {}
  },
  props: {
    total: {},
    currentPage: {},
    pageSize: {},
    pageSizes: {
      type: Array,
      default() {
        return [10, 20, 50, 100, 150, 200, 300, 400, 500, 700, 1000]
      }
    },
    paginationLayout: {
      type: String,
      default() {
        return 'total, sizes, prev, pager, next, jumper'
        // return 'total, sizes, prev, pager, next'
      }
    },
    isSmall: {
      type: Boolean,
      default: true
    }
  },
  created() {},
  mounted() {},
  methods: {
    // 改变每页数量
    handleSizeChange(val) {
      this.$emit('changepages', {
        pageSize: val
      })
    },
    // 改变页数
    handleCurrentChange(val) {
      this.$emit('changepages', {
        pageNum: val
      })
    }
  }
}
</script>
