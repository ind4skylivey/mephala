/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#3b82f6',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#22c55e',
      },
    },
  },
  plugins: [],
}
