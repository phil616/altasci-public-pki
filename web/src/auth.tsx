import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react';

import { APIError, consoleAPI, hasCSRFToken, setCSRFToken } from '@/lib/api';
import type { User } from '@/types';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (input: { login: string; password: string; totp?: string }) => Promise<User>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const session = useQuery({
    queryKey: ['session'],
    queryFn: consoleAPI.session,
    retry: false,
    staleTime: 30_000,
  });

  const clearSession = useCallback(() => {
    setCSRFToken();
    queryClient.setQueryData(['session'], null);
  }, [queryClient]);

  useEffect(() => {
    const unauthorized = () => clearSession();
    window.addEventListener('pki:unauthorized', unauthorized);
    return () => window.removeEventListener('pki:unauthorized', unauthorized);
  }, [clearSession]);

  useEffect(() => {
    if (session.data?.user && !hasCSRFToken()) {
      queryClient.setQueryData(['session'], null);
    }
  }, [queryClient, session.data]);

  const value = useMemo<AuthContextValue>(() => ({
    user: session.data?.user ?? null,
    loading: session.isPending,
    login: async (input) => {
      const result = await consoleAPI.login(input);
      queryClient.setQueryData(['session'], { user: result.user });
      return result.user;
    },
    logout: async () => {
      try {
        await consoleAPI.logout();
      } catch (error) {
        if (!(error instanceof APIError && error.status === 401)) throw error;
      }
      clearSession();
      queryClient.clear();
    },
  }), [clearSession, queryClient, session.data?.user, session.isPending]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
