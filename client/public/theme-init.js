(function () {
  const theme = localStorage.getItem('theme') || 'system'
  const resolved = theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme
  document.documentElement.classList.add(resolved === 'dark' ? 'dark' : 'light')
  document.querySelector('meta[name="theme-color"]').setAttribute('content', resolved === 'dark' ? '#000000' : '#f5f5f7')
})()
