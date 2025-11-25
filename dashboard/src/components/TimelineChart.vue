<template>
  <div style="height: 250px;">
    <Line :data="chartData" :options="chartOptions" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Line } from 'vue-chartjs'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

const props = defineProps({
  data: { type: Array, default: () => [] },
})

const chartData = computed(() => ({
  labels: props.data.map(d => new Date(d.timestamp).toLocaleTimeString()),
  datasets: [{
    label: 'Attacks',
    data: props.data.map(d => d.count),
    borderColor: '#3b82f6',
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    fill: true,
    tension: 0.4,
  }],
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
  },
  scales: {
    x: {
      grid: { color: 'rgba(255,255,255,0.1)' },
      ticks: { color: '#9ca3af' },
    },
    y: {
      grid: { color: 'rgba(255,255,255,0.1)' },
      ticks: { color: '#9ca3af' },
    },
  },
}
</script>
