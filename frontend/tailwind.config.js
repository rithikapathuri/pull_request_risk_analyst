export default {
    content: ['./index.html', './src/**/*.{js,jsx}'],
    theme: {
      extend: {
        colors: {
          surface: '#0f1117',
          panel:   '#161b27',
          border:  '#1e2636',
          muted:   '#4b5675',
          subtle:  '#8b95b0',
          text:    '#e2e8f0',
        },
        fontFamily: {
          sans: ['Inter', 'system-ui', 'sans-serif'],
          mono: ['JetBrains Mono', 'Menlo', 'monospace'],
        },
      },
    },
    plugins: [],
  }