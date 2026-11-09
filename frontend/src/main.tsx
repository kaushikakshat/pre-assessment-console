import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { App } from './App';
import { AuthProvider } from './auth/AuthContext';
import { ToastProvider } from './components';
import { applyTheme } from './lib/theme';
import './styles/tokens.css';
import './styles/app.css';

try {
  const t = localStorage.getItem('pa_theme');
  if (t === 'light' || t === 'dark') applyTheme(t);
} catch { /* storage blocked: follow system theme */ }

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
