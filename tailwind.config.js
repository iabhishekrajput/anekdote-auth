/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./web/templates/**/*.tmpl",
    "./web/ui/**/*.templ",
    "./web/ui/**/*.go"
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#fbbf24',
          hover:   '#f59e0b',
        },
        error:   { DEFAULT: '#f87171', bg: '#450a0a', border: '#991b1b' },
        success: { DEFAULT: '#34d399', bg: '#022c22', border: '#065f46' },
        info:    { DEFAULT: '#38bdf8', bg: '#082f49', border: '#0369a1' },
      },
    },
  },
  plugins: []
};

