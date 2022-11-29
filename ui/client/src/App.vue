<template>
  <div id="app">
    <router-view></router-view>
  </div>
</template>

<script>
export default {
  name: 'App',
  components: {},
  created() {
    Object.keys(this.$store.getters.selectedColumns).forEach((item) => {
      if (sessionStorage.getItem(item)) {
        try {
          this.$store.commit('SET_COLUMNS', { key: item, data: JSON.parse(sessionStorage.getItem(item)) })
        } catch (error) {}
      }
    })
    window.addEventListener('beforeunload', () => {
      Object.keys(this.$store.getters.selectedColumns).forEach((item) => {
        sessionStorage.setItem(item, JSON.stringify(this.$store.getters[item]))
      })
    })
  }
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box !important;
}
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background: #ccd4ec;
}
</style>
