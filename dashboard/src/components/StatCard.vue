<template>
  <div class="card">
    <div class="flex items-center justify-between">
      <div>
        <p class="text-sm text-gray-400">{{ title }}</p>
        <p class="text-2xl font-bold" :class="textColor">{{ value }}</p>
      </div>
      <div class="p-3 rounded-full" :class="bgColor">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path v-if="icon === 'shield'" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          <path v-else-if="icon === 'calendar'" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          <path v-else-if="icon === 'globe'" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          <path v-else stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  title: String,
  value: [String, Number],
  icon: { type: String, default: 'shield' },
  color: { type: String, default: 'red' },
})

const bgColor = computed(() => ({
  'bg-red-900/50': props.color === 'red',
  'bg-blue-900/50': props.color === 'blue',
  'bg-green-900/50': props.color === 'green',
  'bg-yellow-900/50': props.color === 'yellow',
}))

const textColor = computed(() => ({
  'text-red-400': props.color === 'red',
  'text-blue-400': props.color === 'blue',
  'text-green-400': props.color === 'green',
  'text-yellow-400': props.color === 'yellow',
}))
</script>
