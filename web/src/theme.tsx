import { ConfigProvider, theme as antdTheme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';

type ColorMode = 'light' | 'dark';
interface ThemeContextValue { mode: ColorMode; toggle: () => void }

const ThemeContext = createContext<ThemeContextValue>({ mode: 'light', toggle: () => undefined });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ColorMode>(() => {
    try {
      return localStorage.getItem('pki-console.theme') === 'dark' ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  });
  const value = useMemo(() => ({
    mode,
    toggle: () => setMode((current) => {
      const next = current === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem('pki-console.theme', next); } catch { /* Keep the in-memory theme. */ }
      return next;
    }),
  }), [mode]);

  return (
    <ThemeContext.Provider value={value}>
      <ConfigProvider
        locale={zhCN}
        theme={{
          algorithm: mode === 'dark' ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
          cssVar: { prefix: 'pki' },
          token: {
            colorPrimary: '#176b5b',
            colorInfo: '#3b6f8f',
            colorSuccess: '#2f7a5f',
            colorWarning: '#9a671d',
            colorError: '#b5434d',
            borderRadius: 6,
            borderRadiusLG: 8,
            fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
            controlHeight: 38,
          },
          components: {
            Layout: { bodyBg: mode === 'dark' ? '#15191d' : '#f5f6f7', headerBg: 'transparent', siderBg: '#20262d' },
            Menu: { darkItemBg: '#20262d', darkSubMenuItemBg: '#20262d', darkItemSelectedBg: '#36404a' },
            Table: { headerBg: mode === 'dark' ? '#20262d' : '#f6f7f8' },
          },
        }}
      >
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  );
}

export function useColorMode(): ThemeContextValue {
  return useContext(ThemeContext);
}
