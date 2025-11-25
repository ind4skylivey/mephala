import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../services/api'

export const useAttackStore = defineStore('attacks', () => {
  const attacks = ref([])
  const stats = ref(null)
  const loading = ref(false)
  const error = ref(null)

  const recentAttacks = computed(() => attacks.value.slice(0, 50))

  async function fetchAttacks(params = {}) {
    loading.value = true
    try {
      const response = await api.getAttacks(params)
      attacks.value = response.items
      return response
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchStats() {
    try {
      stats.value = await api.getStats()
    } catch (e) {
      error.value = e.message
    }
  }

  function addAttack(attack) {
    attacks.value.unshift(attack)
    if (attacks.value.length > 100) {
      attacks.value = attacks.value.slice(0, 100)
    }
  }

  return {
    attacks,
    stats,
    loading,
    error,
    recentAttacks,
    fetchAttacks,
    fetchStats,
    addAttack,
  }
})
