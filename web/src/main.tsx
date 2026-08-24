import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App as AntApp } from 'antd';
import 'antd/dist/reset.css';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import App from './App';
import { handleVitePreloadError } from './lib/preload-recovery';
import { ThemeProvider } from './theme';
import './styles.css';

let preloadRecoveryStorage: Storage | undefined;
try {
  preloadRecoveryStorage = window.sessionStorage;
} catch {
  // Some hardened browser profiles disable session storage.
}

window.addEventListener('vite:preloadError', (event) => {
  handleVitePreloadError(event, preloadRecoveryStorage, () => window.location.reload());
});

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 15_000, retry: 1, refetchOnWindowFocus: true },
    mutations: { retry: false },
  },
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AntApp>
          <BrowserRouter><App /></BrowserRouter>
        </AntApp>
      </ThemeProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
