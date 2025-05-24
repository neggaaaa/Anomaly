/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        'primary': {
          DEFAULT: '#3b82f6',
          '50': '#eff6ff',
          '100': '#dbeafe',
          '200': '#bfdbfe',
          '300': '#93c5fd',
          '400': '#60a5fa',
          '500': '#3b82f6',
          '600': '#2563eb',
          '700': '#1d4ed8',
          '800': '#1e40af',
          '900': '#1e3a8a',
        },
        'success': {
          DEFAULT: '#10b981',
          '50': '#ecfdf5',
          '500': '#10b981',
          '700': '#047857',
        },
        'warning': {
          DEFAULT: '#f59e0b',
          '50': '#fffbeb',
          '500': '#f59e0b',
          '700': '#b45309',
        },
        'danger': {
          DEFAULT: '#ef4444',
          '50': '#fef2f2',
          '500': '#ef4444',
          '700': '#b91c1c',
        },
        'dark': {
          '50': '#f8fafc',
          '100': '#f1f5f9',
          '200': '#e2e8f0',
          '300': '#cbd5e1',
          '400': '#94a3b8',
          '500': '#64748b',
          '600': '#475569',
          '700': '#334155',
          '800': '#1e293b',
          '900': '#0f172a',
          '950': '#020617',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
    },
  },
  plugins: [],
}