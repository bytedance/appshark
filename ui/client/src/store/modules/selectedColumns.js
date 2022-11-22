const state = {
  titleColumn: [],
  playManageDefaultTable: [] // 剧本管理-表格
}

const mutations = {
  SET_COLUMNS: (state, { key, data }) => {
    state[key] = data
  }
}

export default {
  state,
  mutations
}
