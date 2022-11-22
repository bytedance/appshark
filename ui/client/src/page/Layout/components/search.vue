<template>
  <serch-slot>
    <div slot="left_header" class="search_left">
      <el-form-item label="位 置:">
        <el-input clearable v-model="searchParams.position" placeholder="请输入位置"> </el-input>
      </el-form-item>
      <el-form-item label="堆 栈:">
        <el-input v-model="searchParams.target" placeholder="请输入堆栈"></el-input>
      </el-form-item>
    </div>
    <div slot="right_header" class="search_right">
      <el-button type="primary" size="small" @click="onSearch(false)">搜 索</el-button>
      <el-button type="default" size="small" @click="resetSearch(true)">重 置</el-button>
    </div>
    <div slot="footer" class="search_left"></div>
  </serch-slot>
</template>

<script>
import serchSlot from '@/components/serchSlot'
export default {
  name: 'searchForm',
  inject: {
    user: {
      from: 'user',
      default: () => {
        return {}
      }
    }
  },
  components: { serchSlot },
  props: {},
  data() {
    return {
      searchParams: {
        position: '',
        target: ''
      }
    }
  },
  methods: {
    resetSearch(reset) {
      // 重置搜索
      this.searchParams = {
        position: '',
        target: ''
      }
      this.onSearch(reset)
    },

    onSearch(reset) {
      this.$emit('handleSearch', this.searchParams, reset)
    }
  },
  mounted() {}
}
</script> 

<style lang="scss" scoped>
.default-search::after {
  content: '';
  display: block;
  clear: both;
}
.search_left {
  width: calc(100% - 260px);
  .el-form-item {
    width: 45%;
    margin-right: 3%;
    float: left;
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
</style>