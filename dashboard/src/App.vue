<template>
  <div class="min-h-screen bg-gray-900 text-gray-100">
    <nav class="bg-gray-800 border-b border-gray-700">
      <div class="max-w-7xl mx-auto px-4">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center">
            <span class="text-xl font-bold text-primary">HoneyTrap</span>
            <div class="ml-10 flex space-x-4">
              <router-link to="/" class="nav-link">Dashboard</router-link>
              <router-link to="/attacks" class="nav-link">Attacks</router-link>
              <router-link to="/map" class="nav-link">Map</router-link>
            </div>
          </div>
          <div class="flex items-center space-x-4">
            <span class="text-sm text-gray-400">
              <span class="inline-block w-2 h-2 rounded-full mr-2" 
                    :class="connected ? 'bg-green-500' : 'bg-red-500'"></span>
              {{ connected ? 'Live' : 'Disconnected' }}
            </span>
          </div>
        </div>
      </div>
    </nav>
    <main class="max-w-7xl mx-auto px-4 py-6">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useAttackStore } from './stores/attackStore'

const store = useAttackStore()
const connected = ref(false)
let ws = null

onMounted(() => {
  connectWebSocket()
})

onUnmounted(() => {
  if (ws) ws.close()
})

function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${protocol}//${window.location.host}/ws/live`)
  
  ws.onopen = () => {
    connected.value = true
  }
  
  ws.onclose = () => {
    connected.value = false
    setTimeout(connectWebSocket, 5000)
  }
  
  ws.onmessage = (event) => {
    const data = JSON.parse(event.data)
    if (data.event === 'attack') {
      store.addAttack(data.data)
    }
  }
}
</script>

<style scoped>
.nav-link {
  @apply px-3 py-2 rounded-md text-sm font-medium text-gray-300 hover:bg-gray-700 hover:text-white;
}
.router-link-active {
  @apply bg-gray-900 text-white;
}
</style>
