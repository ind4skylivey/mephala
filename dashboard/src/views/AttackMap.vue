<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-bold">Attack Map</h1>
    <div class="card" style="height: 600px;">
      <div id="map" style="height: 100%; border-radius: 0.5rem;"></div>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="card">
        <h2 class="text-lg font-semibold mb-4">Top Attack Origins</h2>
        <div class="space-y-2">
          <div v-for="geo in geoData" :key="geo.country_code" 
               class="flex justify-between items-center py-2 border-b border-gray-700">
            <span>{{ geo.country_name }}</span>
            <span class="font-bold">{{ geo.count }}</span>
          </div>
        </div>
      </div>
      <div class="card">
        <h2 class="text-lg font-semibold mb-4">Top Attackers</h2>
        <div class="space-y-2">
          <div v-for="attacker in topAttackers" :key="attacker.ip"
               class="flex justify-between items-center py-2 border-b border-gray-700">
            <span class="font-mono text-sm">{{ attacker.ip }}</span>
            <span class="font-bold">{{ attacker.attack_count }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import L from 'leaflet'
import api from '../services/api'

const geoData = ref([])
const topAttackers = ref([])
let map = null

onMounted(async () => {
  map = L.map('map').setView([20, 0], 2)
  
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    maxZoom: 19,
  }).addTo(map)

  geoData.value = await api.getGeoData()
  topAttackers.value = await api.getTopAttackers()

  geoData.value.forEach(point => {
    if (point.latitude && point.longitude) {
      const radius = Math.min(Math.max(point.count / 10, 5), 30)
      L.circleMarker([point.latitude, point.longitude], {
        radius,
        fillColor: '#ef4444',
        color: '#dc2626',
        weight: 1,
        opacity: 0.8,
        fillOpacity: 0.6,
      })
      .addTo(map)
      .bindPopup(`<b>${point.country_name}</b><br>${point.count} attacks`)
    }
  })
})
</script>
