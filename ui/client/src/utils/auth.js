import Cookies from 'js-cookie'

const TokenKey = 'jwtToken'

export function getToken() {
  // return Cookies.get(TokenKey)
  return localStorage.getItem('appShark_token')
}

export function setToken(token) {
  return Cookies.set(TokenKey, token)
}

export function removeToken() {
  return Cookies.remove(TokenKey)
}
