import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Attacks from '../views/Attacks.vue'
import AttackMap from '../views/AttackMap.vue'

const routes = [
  { path: '/', name: 'Dashboard', component: Dashboard },
  { path: '/attacks', name: 'Attacks', component: Attacks },
  { path: '/map', name: 'Map', component: AttackMap },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
