<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-bold">Dashboard</h1>
    
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard title="Total Attacks" :value="stats?.total_attacks || 0" icon="shield" />
      <StatCard title="Today" :value="stats?.attacks_today || 0" icon="calendar" color="blue" />
      <StatCard title="Unique IPs" :value="stats?.unique_ips || 0" icon="globe" color="green" />
      <StatCard title="Avg Severity" :value="stats?.avg_severity?.toFixed(1) || '0'" icon="alert" color="yellow" />
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="card">
        <h2 class="text-lg font-semibold mb-4">Attack Timeline</h2>
        <TimelineChart :data="timelineData" />
      </div>
      <div class="card">
        <h2 class="text-lg font-semibold mb-4">Attack Types</h2>
        <AttackTypesChart :data="attackTypes" />
      </div>
    </div>

    <div class="card">
      <h2 class="text-lg font-semibold mb-4">Live Attack Feed</h2>
      <LiveFeed :attacks="recentAttacks" />
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useAttackStore } from '../stores/attackStore'
import api from '../services/api'
import StatCard from '../components/StatCard.vue'
import TimelineChart from '../components/TimelineChart.vue'
import AttackTypesChart from '../components/AttackTypesChart.vue'
import LiveFeed from '../components/LiveFeed.vue'

const store = useAttackStore()
const stats = computed(() => store.stats)
const recentAttacks = computed(() => store.recentAttacks)
const timelineData = ref([])
const attackTypes = ref([])

onMounted(async () => {
  await store.fetchStats()
  await store.fetchAttacks({ page_size: 50 })
  timelineData.value = await api.getTimeline(24)
  attackTypes.value = await api.getAttackTypes()
})
</script>
