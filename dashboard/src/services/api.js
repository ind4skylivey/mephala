import axios from 'axios'

const client = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export default {
  async login(username, password) {
    const response = await client.post('/auth/login', { username, password })
    localStorage.setItem('token', response.data.access_token)
    return response.data
  },

  async getAttacks(params = {}) {
    const response = await client.get('/attacks', { params })
    return response.data
  },

  async getAttack(id) {
    const response = await client.get(`/attacks/${id}`)
    return response.data
  },

  async getStats() {
    const response = await client.get('/stats/overview')
    return response.data
  },

  async getTimeline(hours = 24) {
    const response = await client.get('/stats/timeline', { params: { hours } })
    return response.data
  },

  async getGeoData() {
    const response = await client.get('/stats/geographic')
    return response.data
  },

  async getTopAttackers() {
    const response = await client.get('/stats/top-attackers')
    return response.data
  },

  async getAttackTypes() {
    const response = await client.get('/stats/attack-types')
    return response.data
  },
}
