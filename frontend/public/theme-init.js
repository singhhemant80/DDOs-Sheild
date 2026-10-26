// Applies the saved theme before first paint (kept out of index.html so the CSP needs no 'unsafe-inline').
try { var t = localStorage.getItem("shield-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
