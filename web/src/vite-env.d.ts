/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PKI_SURFACE?: 'auto' | 'console' | 'public';
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
