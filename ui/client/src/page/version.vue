<template>
  <ul class="main_box">
    <!-- 头部 START -->
    <div class="v1-maintcontent-head">
      <div class="v1-user">
        <span class="v1-user-title">
          <span>AppShark应用检测平台</span>
        </span>
        <div class="v1-serach-box-p">
          <el-dropdown
            class="avatar-container"
            @command="handleCommand"
            @visible-change="visibleChange"
            trigger="click"
          >
            <div class="avatar-wrapper">
              <img src="../assets/img/icon-head.png" style="width: 36px; height: 36px" />
              <span class="v1-serach-name">管理员</span>
              <span :class="visibleDown ? 'el-icon-caret-top' : 'el-icon-caret-bottom'"></span>
            </div>
            <el-dropdown-menu slot="dropdown">
              <el-dropdown-item class="dropdown-wrap" command="logout">
                <span>退出</span>
              </el-dropdown-item>
            </el-dropdown-menu>
          </el-dropdown>
        </div>
      </div>
    </div>
    <!-- 头部 END -->

    <li>
      <div>
        <span>
          <img src="../assets/img/icon-check.png" alt="" />
          <i>合规检测</i>
        </span>
      </div>
    </li>
    <li>
      <div class="v1-main-content-main">
        <!-- <current-position></current-position> -->
        <el-tabs class="nav-tabs" type="card" @tab-click="clickTab">
          <el-tab-pane :key="item.title" v-for="item in tabs" :label="item.title" :name="item.title" class="pointer">
          </el-tab-pane>
        </el-tabs>

        <transition name="fade" mode="out-in">
          <router-view></router-view>
        </transition>
      </div>
    </li>
  </ul>
</template>

<script>
export default {
  name: 'page404',
  data() {
    return {
      tabs: [{ title: '合规检测' }],
      visibleDown: false
    }
  },
  methods: {
    clickTab() {
      this.$router.push({ name: 'list' })
    },
    visibleChange(visible) {
      this.visibleDown = visible
    },
    handleCommand(item) {
      if (item === 'logout') {
        this.logout()
      }
    },
    logout() {
      this.$confirm('确定退出吗?', '温馨提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消'
      })
        .then(() => {
          localStorage.removeItem('appShark_token')
          this.$router.push({ name: 'index' })
        })
        .catch(() => {})
    }
  }
}
</script>

<style  lang="scss" scoped>
.main_box {
  widows: 100%;
  height: 100%;

  > li {
    float: left;
  }
  > li:nth-of-type(1) {
    width: 94px;
    background: #ccd4ec;
    height: 100%;
    padding-bottom: 60px;
    > div {
      width: calc(100% - 4px);
      padding-top: 20px;
      margin-left: -4px;
      height: 100%;
      background: linear-gradient(180deg, #0c2676 0%, #1836a4 63%, #0098d5 100%);
      margin-top: 60px;
      > span {
        width: 94px;
        height: 86px;
        float: left;
        background: linear-gradient(180deg, #1699ff 0%, #513be0 100%);
        border-radius: 4px;
        text-align: center;
        padding: 15px 0 0 0;
        i {
          font-size: 14px;
          font-weight: bold;
          font-style: normal;
          color: #fff;
          display: block;
          line-height: 25px;
        }
        img {
          width: 30px;
          height: 30px;
        }
      }
    }
  }
  > li:nth-of-type(2) {
    width: calc(100% - 100px);
    height: 100%;
  }
  ::v-deep .search_right {
    .el-button--small {
      width: 80px;
    }
  }
  .v1-main-content-main {
    width: 100%;
    // height: calc(100% - 15px);
    height: 100%;
    background: #ccd4ec;
    overflow-y: auto;
    padding: 20px 20px 20px 12px;
    box-sizing: border-box;
    .nav-tabs {
      margin-bottom: 1px;
      margin-top: 60px;
      ::v-deep .el-tabs__header {
        border-bottom: 0;
        margin: 0;
      }
      ::v-deep .el-icon-close:hover {
        color: #409eff;
        background: transparent;
      }
      ::v-deep .el-tabs__nav.is-top {
        color: #409eff;
        background: transparent;
        cursor: pointer !important;
      }
      ::v-deep .el-tabs__nav {
        border-radius: 8px 8px 0 0;
        & :first-child {
          border-radius: 8px 0px 0px 0px !important;
          cursor: pointer !important;
        }
        & :last-child {
          border-radius: 0px 8px 0px 0px;
        }
      }

      ::v-deep .el-tabs__item {
        min-width: 100px;
        height: 36px;
        line-height: 36px;
        border: 0;
        background: #dbe1f1;
        text-align: center;
        cursor: default !important;
      }
      ::v-deep .el-tabs__item.is-active {
        border-bottom: 0;
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.9) 0%, rgba(255, 255, 255, 0.6) 100%);
      }
      ::v-deep .el-tabs__nav-wrap.is-scrollable {
        background: #dbe1f1;
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
      }
      ::v-deep .el-tabs__nav-prev {
        line-height: 36px;
      }
      ::v-deep .el-tabs__nav-next {
        line-height: 36px;
      }
    }
  }
}
.v1-maintcontent-head {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 60px;
  transition: left 0.3s;
  background: rgba(255, 255, 255, 1);
  box-shadow: 1px 1px 4px 0px rgba(72, 99, 129, 0.2);
  z-index: 10;
}
.v1-user {
  height: 100%;
  background: rgba(255, 255, 255, 1);
  border-radius: 6px;
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: space-between;
  background: url('../assets/img/header-bg.png') 100% 100% no-repeat;
}
.v1-user-title {
  margin-left: 5px;
  font-size: 18px;
  font-family: AppleSystemUIFont;
  color: rgba(38, 38, 38, 1);
  letter-spacing: 1px;
  font-weight: 600;
  display: flex;
  align-items: center;
}
.v1-serach-box-p {
  display: flex;
  flex-direction: row;
  align-items: center;
  margin-right: 30px;
  .notice-group {
    margin-right: 45px;
    position: relative;
    cursor: pointer;
    img {
      width: 28px;
      height: 28px;
    }
    span {
      min-width: 25px;
      padding: 0 2px;
      height: 18px;
      line-height: 18px;
      font-size: 14px;
      position: absolute;
      background: #ff4d4f;
      border-radius: 9px;
      text-align: center;
      top: 5px;
      right: -10px;
      color: #ffffff;
    }
  }
}
.avatar-container {
  cursor: pointer;
}
.avatar-wrapper {
  display: inline-flex;
  align-items: center;
}
.v1-serach-name {
  font-size: 14px;
  font-family: MicrosoftYaHei;
  color: rgba(0, 0, 0, 0.65);
  margin-right: 14px;
  margin-left: 10px;
}
</style>
