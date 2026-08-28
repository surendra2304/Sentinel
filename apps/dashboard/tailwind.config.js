/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          950: '#030712',
          900: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          cyan: '#06b6d4',
          crimson: '#ef4444',
          amber: '#f59e0b',
          emerald: '#10b981',
        },
      },
    },
  },
  plugins: [],
};
