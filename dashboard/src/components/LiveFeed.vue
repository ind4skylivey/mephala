<template>
  <div class="space-y-2 max-h-96 overflow-y-auto">
    <div v-for="attack in attacks" :key="attack.id"
         class="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg hover:bg-gray-700 transition-colors">
      <div class="flex items-center space-x-4">
        <span class="w-2 h-2 rounded-full animate-pulse" :class="severityDot(attack.severity)"></span>
        <span class="font-mono text-sm">{{ attack.source_ip }}</span>
        <span class="px-2 py-0.5 rounded text-xs" :class="serviceClass(attack.service_type)">
          {{ attack.service_type.toUpperCase() }}
        </span>
        <span class="text-gray-400 text-sm">{{ attack.attack_type || 'scanning' }}</span>
      </div>
      <div class="flex items-center space-x-4">
        <span class="text-sm text-gray-400">{{ attack.country_code || '-' }}</span>
        <span class="text-xs text-gray-500">{{ formatTime(attack.timestamp) }}</span>
      </div>
    </div>
    <div v-if="attacks.length === 0" class="text-center text-gray-500 py-8">
      No attacks recorded yet
    </div>
  </div>
</template>

<script setup>
defineProps({
  attacks: { type: Array, default: () => [] },
})

function formatTime(ts) {
  const date = new Date(ts)
  return date.toLocaleTimeString()
}

function serviceClass(service) {
  return {
    ssh: 'bg-blue-600',
    http: 'bg-green-600',
    ftp: 'bg-purple-600',
  }[service] || 'bg-gray-600'
}

function severityDot(severity) {
  if (severity >= 8) return 'bg-red-500'
  if (severity >= 5) return 'bg-yellow-500'
  return 'bg-green-500'
}
</script>
