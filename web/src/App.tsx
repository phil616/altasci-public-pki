import { Result, Button } from 'antd';
import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { AuthProvider, useAuth } from '@/auth';
import { ConsoleLayout } from '@/components/ConsoleLayout';
import { LoadingScreen } from '@/components/common';
import { can, type Capability } from '@/lib/permissions';

const AuditPage = lazy(() => import('@/pages/AuditPage').then((module) => ({ default: module.AuditPage })));
const AuthoritiesPage = lazy(() => import('@/pages/AuthoritiesPage').then((module) => ({ default: module.AuthoritiesPage })));
const AuthorityDetailPage = lazy(() => import('@/pages/AuthorityDetailPage').then((module) => ({ default: module.AuthorityDetailPage })));
const CertificateDetailPage = lazy(() => import('@/pages/CertificateDetailPage').then((module) => ({ default: module.CertificateDetailPage })));
const CertificatesPage = lazy(() => import('@/pages/CertificatesPage').then((module) => ({ default: module.CertificatesPage })));
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then((module) => ({ default: module.DashboardPage })));
const LoginPage = lazy(() => import('@/pages/LoginPage').then((module) => ({ default: module.LoginPage })));
const PublicModule = lazy(() => import('@/pages/PublicPage').then((module) => ({ default: module.PublicLayout })));
const PublicAboutPage = lazy(() => import('@/pages/PublicPage').then((module) => ({ default: module.PublicAboutPage })));
const PublicCertificatePage = lazy(() => import('@/pages/PublicPage').then((module) => ({ default: module.PublicCertificatePage })));
const PublicHomePage = lazy(() => import('@/pages/PublicPage').then((module) => ({ default: module.PublicHomePage })));
const PublicLookupPage = lazy(() => import('@/pages/PublicPage').then((module) => ({ default: module.PublicLookupPage })));
const RequestDetailPage = lazy(() => import('@/pages/RequestDetailPage').then((module) => ({ default: module.RequestDetailPage })));
const RequestsPage = lazy(() => import('@/pages/RequestsPage').then((module) => ({ default: module.RequestsPage })));
const UsersPage = lazy(() => import('@/pages/UsersPage').then((module) => ({ default: module.UsersPage })));
const UtilitiesPage = lazy(() => import('@/pages/UtilitiesPage').then((module) => ({ default: module.UtilitiesPage })));

function isPublicSurface(): boolean {
  const surface = document.querySelector<HTMLMetaElement>('meta[name="pki-surface"]')?.content;
  if (surface === 'public') return true;
  if (surface === 'console') return false;
  const override = import.meta.env.VITE_PKI_SURFACE;
  if (override === 'public') return true;
  if (override === 'console') return false;
  const hostname = window.location.hostname.toLowerCase();
  return hostname === 'pki.localhost' || (hostname.startsWith('pki.') && !hostname.includes('console'));
}

export default function App() {
  return <Suspense fallback={<LoadingScreen />}>{isPublicSurface() ? <PublicRoutes /> : <AuthProvider><ConsoleRoutes /></AuthProvider>}</Suspense>;
}

function ProtectedRoute() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <LoadingScreen />;
  return user ? <ConsoleLayout /> : <Navigate to="/login" replace state={{ from: location.pathname }} />;
}

function ConsoleRoutes() {
  return <Routes><Route path="/login" element={<LoginPage />} /><Route element={<ProtectedRoute />}><Route index element={<DashboardPage />} /><Route path="authorities" element={<AuthoritiesPage />} /><Route path="authorities/:id" element={<AuthorityDetailPage />} /><Route path="requests" element={<RequestsPage />} /><Route path="requests/:id" element={<RequestDetailPage />} /><Route path="certificates" element={<CertificatesPage />} /><Route path="certificates/:id" element={<CertificateDetailPage />} /><Route path="users" element={<RequireCapability capability="manage_users"><UsersPage /></RequireCapability>} /><Route path="audit" element={<RequireCapability capability="read_audit"><AuditPage /></RequireCapability>} /><Route path="utilities" element={<UtilitiesPage />} /></Route><Route path="*" element={<NotFound />} /></Routes>;
}

function PublicRoutes() {
  return <Routes><Route element={<PublicModule />}><Route index element={<PublicHomePage />} /><Route path="lookup" element={<PublicLookupPage />} /><Route path="about" element={<PublicAboutPage />} /><Route path="certificate/:fingerprint" element={<PublicCertificatePage />} /><Route path="*" element={<NotFound />} /></Route></Routes>;
}

function RequireCapability({ capability, children }: { capability: Capability; children: ReactNode }) {
  const { user } = useAuth();
  return can(user?.role, capability) ? children : <Result status="403" title="无权访问" subTitle="当前角色没有访问此视图的权限。" extra={<Button type="primary" href="/">返回控制台</Button>} />;
}

function NotFound() {
  return <Result status="404" title="页面不存在" subTitle="请求的页面不存在或当前身份无权访问。" extra={<Button type="primary" href="/">返回首页</Button>} />;
}
