

<template>
  <div :class="['bgcolor', 'box_search', activeFlag ? 'active' : '']">
    <div>
      <el-form ref="refForm" :label-width="labelWidth" class="searchList" style="width: 100%; margin: 0">
        <slot name="left_header"></slot>
        <slot name="right_header"></slot>
      </el-form>
      <el-form ref="refForm" :label-width="labelWidth" class="default-search2 usernameSearch2">
        <slot name="footer"></slot>
      </el-form>
    </div>
    <template v-if="showSpan">
      <span class="span" v-if="activeFlag" @click="activeFlag = !activeFlag"
        >收起 <i class="el-icon-arrow-up"></i
      ></span>
      <span class="span" v-else @click="activeFlag = !activeFlag">展开 <i class="el-icon-arrow-right"></i></span>
    </template>
  </div>
</template>

<script>
export default {
  props: {
    labelWidth: {
      type: String,
      default: '100px'
    },
    showSpan: {
      type: Boolean,
      default: false
    }
  },
  data() {
    return {
      activeFlag: false
    }
  },
  methods: {
    changeFn() {
      this.activeFlag = !activeFlag
    }
  }
}
</script>
<style lang='scss' scoped>
.searchList::after,
.default-search2::after {
  content: '';
  display: block;
  clear: both;
}
.box_search {
  width: 100%;
  height: 70px;
  overflow: hidden;
  transition: 0.3s linear;
  position: relative;
  padding: 5px 0 0px 0px;
}
.active {
  transition: 0.3s linear;
  height: auto;
}
::v-deep .el-collapse-item__wrap {
  border: none !important;
}
::v-deep .el-collapse-item__header {
  height: auto !important;
  padding: 0 !important;
  border: none;
  position: relative;
}
::v-deep .el-collapse-item__arrow {
  position: absolute;
  right: 0%;
  top: 41%;
}
::v-deep .el-date-editor--daterange {
  width: 100%;
}
::v-deep .el-collapse-item__content {
  padding-bottom: 5px;
}
.searchList {
  padding: 10px 15px;
  display: flex;
  // justify-content: center;
  justify-content: flex-start;
  align-items: center;
  margin: 0;
  // background: linear-gradient(180deg, #ffffff 0%, rgba(255, 255, 255, 0.7) 100%);
}
.default-search2 {
  padding: 10px 15px;
  // padding: 0px 10px 10px 20px;
  // background: linear-gradient(180deg, #ffffff 0%, rgba(255, 255, 255, 0.7) 100%);
}
.usernameSearch2 {
  display: flex;
  justify-content: flex-start;
  align-items: center;
  margin: 0;
}
::v-deep .el-collapse-item__arrow {
  display: none;
}
.span {
  position: absolute;
  right: 0;
  top: 20px;
  cursor: pointer;
  color: #409eff;
  width: 80px;
  height: 30px;
  line-height: 30px;
  text-align: center;
  font-size: 14px;
}
.bgcolor {
  background: linear-gradient(180deg, #ffffff 0%, rgba(255, 255, 255, 0.7) 100%);
}
</style>
