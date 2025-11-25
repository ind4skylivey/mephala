<template>
  <div style="height: 250px;">
    <Doughnut :data="chartData" :options="chartOptions" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps({
  data: { type: Array, default: () => [] },
})

const colors = [
  '#ef4444', '#f59e0b', '#22c55e', '#3b82f6', 
  '#8b5cf6', '#ec4899', '#14b8a6', '#f97316',
]

const chartData = computed(() => ({
  labels: props.data.map(d => d.attack_type),
  datasets: [{
    data: props.data.map(d => d.count),
    backgroundColor: colors.slice(0, props.data.length),
    borderWidth: 0,
  }],
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'right',
      labels: { color: '#9ca3af' },
    },
  },
}
</script>
