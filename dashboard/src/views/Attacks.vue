<template>
  <div class="space-y-6">
    <div class="flex justify-between items-center">
      <h1 class="text-2xl font-bold">Attacks</h1>
      <div class="flex space-x-2">
        <select v-model="filters.service_type" @change="loadAttacks" 
                class="bg-gray-700 rounded px-3 py-2 text-sm">
          <option value="">All Services</option>
          <option value="ssh">SSH</option>
          <option value="http">HTTP</option>
          <option value="ftp">FTP</option>
        </select>
        <select v-model="filters.attack_type" @change="loadAttacks"
                class="bg-gray-700 rounded px-3 py-2 text-sm">
          <option value="">All Types</option>
          <option value="brute_force">Brute Force</option>
          <option value="sql_injection">SQL Injection</option>
          <option value="xss">XSS</option>
          <option value="rce">RCE</option>
        </select>
      </div>
    </div>

    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-4 py-3 text-left text-sm">Time</th>
            <th class="px-4 py-3 text-left text-sm">Source IP</th>
            <th class="px-4 py-3 text-left text-sm">Service</th>
            <th class="px-4 py-3 text-left text-sm">Type</th>
            <th class="px-4 py-3 text-left text-sm">Severity</th>
            <th class="px-4 py-3 text-left text-sm">Country</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-700">
          <tr v-for="attack in attacks" :key="attack.id" 
              class="hover:bg-gray-750 cursor-pointer"
              @click="showDetails(attack)">
            <td class="px-4 py-3 text-sm text-gray-400">{{ formatTime(attack.timestamp) }}</td>
            <td class="px-4 py-3 text-sm font-mono">{{ attack.source_ip }}</td>
            <td class="px-4 py-3 text-sm">
              <span class="px-2 py-1 rounded text-xs" :class="serviceClass(attack.service_type)">
                {{ attack.service_type.toUpperCase() }}
              </span>
            </td>
            <td class="px-4 py-3 text-sm">{{ attack.attack_type || 'unknown' }}</td>
            <td class="px-4 py-3 text-sm">
              <span :class="severityClass(attack.severity)">{{ attack.severity }}</span>
            </td>
            <td class="px-4 py-3 text-sm">{{ attack.country_code || '-' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="flex justify-between items-center">
      <span class="text-sm text-gray-400">Total: {{ total }} attacks</span>
      <div class="flex space-x-2">
        <button @click="prevPage" :disabled="page === 1" class="btn btn-primary">Previous</button>
        <span class="px-4 py-2">Page {{ page }} of {{ pages }}</span>
        <button @click="nextPage" :disabled="page >= pages" class="btn btn-primary">Next</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import api from '../services/api'

const attacks = ref([])
const page = ref(1)
const pages = ref(1)
const total = ref(0)
const filters = reactive({
  service_type: '',
  attack_type: '',
})

async function loadAttacks() {
  const response = await api.getAttacks({ page: page.value, ...filters })
  attacks.value = response.items
  pages.value = response.pages
  total.value = response.total
}

function prevPage() {
  if (page.value > 1) {
    page.value--
    loadAttacks()
  }
}

function nextPage() {
  if (page.value < pages.value) {
    page.value++
    loadAttacks()
  }
}

function formatTime(ts) {
  return new Date(ts).toLocaleString()
}

function serviceClass(service) {
  const classes = {
    ssh: 'bg-blue-600',
    http: 'bg-green-600',
    ftp: 'bg-purple-600',
  }
  return classes[service] || 'bg-gray-600'
}

function severityClass(severity) {
  if (severity >= 8) return 'severity-critical font-bold'
  if (severity >= 6) return 'severity-high'
  if (severity >= 4) return 'severity-medium'
  return 'severity-low'
}

function showDetails(attack) {
  console.log('Attack details:', attack)
}

onMounted(loadAttacks)
</script>
