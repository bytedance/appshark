<template>
  <div class="content">
    <input type="checkbox" id="exp" v-show="false" />
    <div :class="{ text: isShowZK }" id="textContainer">
      <div class="text more" ref="more"></div>
      <label class="showMore" for="exp" v-if="isShowZK"></label>
      {{ textDetails }}
    </div>
  </div>
</template>

<script>
export default {
  name: 'elli',
  props: {
    textDetails: ''
  },
  data() {
    return { isShowZK: false }
  },
  created() {},
  mounted() {
    // DOM 加载完执行
  },
  watch: {
    textDetails() {
      this.$nextTick(() => {
        let oneHeight = this.$refs.more.scrollHeight
        let threeHeight = oneHeight * 3 || 99
        let h = document.querySelector('#textContainer').scrollHeight
        if (h > threeHeight) {
          //展开和关闭按钮的显示和隐藏
          this.isShowZK = true
        } else {
          this.isShowZK = false
        }
      })
    }
  }
}
</script>

<style  lang="scss" scoped>
.showMore {
  float: right;
  clear: both;
  margin-right: 8px;
  line-height: 12px;
  font-size: 13px;
  color: #02a7f0;
  cursor: pointer;
}
.text::before {
  content: '';
  float: right;
  margin-bottom: -18px;
  height: 100%;
  cursor: pointer;
}
#textContainer {
  padding: 8px 0 0 0;
  line-height: 25px;
}
.content {
  display: flex;
}
.text {
  display: -webkit-box;
  overflow: hidden;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
}
#exp {
  visibility: hidden;
}
#exp:checked + .text {
  -webkit-line-clamp: 999;
}
.showMore::after {
  content: '展开';
}
#exp:checked + .text .showMore::after {
  content: '收起';
}
</style>
