import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Security: Disable right-click context menu in production
if (process.env.NODE_ENV === 'production') {
  document.addEventListener('contextmenu', (e) => e.preventDefault());
  
  // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
  document.addEventListener('keydown', (e) => {
    if (
      e.key === 'F12' ||
      (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
      (e.ctrlKey && e.key === 'U')
    ) {
      e.preventDefault();
    }
  });
}

// Security headers check
if (process.env.NODE_ENV === 'production') {
  // Check if running over HTTPS
  if (location.protocol !== 'https:') {
    console.warn('Government portal should be served over HTTPS');
  }
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
