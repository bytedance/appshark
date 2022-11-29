<template>
  <div class="container">
    <el-card shadow="never" class="default-card margin-top-14" v-loading="assignmentLoading">
      <div slot="header">已选规则</div>
    </el-card>
  </div>
</template>

<script>
export default {
  name: 'index',
  data() {
    return {
      assignmentLoading: false
    }
  },
  methods: {
    sure() {}
  },
  created() {
    let rules = localStorage.getItem('rules')
    console.log(rules)
  }
}
</script>

<style lang="scss" scoped>
.container {
  width: 100%;
  background: #eaedf7;
  box-shadow: 1px 1px 4px 0 rgba(72, 99, 129, 0.2);
  border-radius: 0 8px 8px 8px;
  overflow: auto;
  padding: 0 15px 15px 15px;
}
</style>
