/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#f8fafc', // Slate 50 (clean light background)
        primary: '#3b82f6', // Corporate Royal Blue
        secondary: '#ffffff', // Pure white for cards/panels
        accent: '#ef4444', // Red
        danger: '#ef4444',
        warning: '#f59e0b', // Amber
        success: '#10b981', // Emerald Green
        // Invert default white/black classes to guarantee light mode text contrast
        white: '#0f172a', // text-white will render as dark slate text
        black: '#ffffff', // bg-black will render as pure white container
        // Invert gray palette so that text-gray-100/text-gray-200 are dark slate,
        // and bg-gray-800/bg-gray-900 are light gray/off-white.
        gray: {
          50: '#0f172a',
          100: '#1e293b',
          200: '#334155',
          300: '#475569',
          400: '#64748b',
          500: '#94a3b8',
          600: '#cbd5e1',
          700: '#e2e8f0',
          800: '#f1f5f9',
          900: '#f8fafc',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
