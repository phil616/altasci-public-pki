import type {
  AuditRecord,
  CAGrant,
  Certificate,
  CertificateInventoryItem,
  CertificateInventoryStatus,
  CertificateAuthority,
  CertificateRequest,
  CertificateStatus,
  ListResponse,
  LoginResponse,
  Problem,
  SigningProfile,
  TimestampAuthority,
  Subject,
  User,
  VersionInfo,
} from '@/types';

const CSRF_STORAGE_KEY = 'pki-console.csrf';
const consoleBase = '/api/v1';

export class APIError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestID?: string;

  constructor(problem: Problem) {
    super(problem.detail || problem.title || '请求失败');
    this.name = 'APIError';
    this.status = problem.status;
    this.code = problem.code || 'request_failed';
    this.requestID = problem.request_id;
  }
}

export function setCSRFToken(token?: string): void {
  if (token) localStorage.setItem(CSRF_STORAGE_KEY, token);
  else localStorage.removeItem(CSRF_STORAGE_KEY);
}

export function hasCSRFToken(): boolean {
  return Boolean(localStorage.getItem(CSRF_STORAGE_KEY));
}

function isUnsafe(method: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
}

async function parseError(response: Response): Promise<APIError> {
  let body: Partial<Problem> = {};
  try {
    body = (await response.json()) as Partial<Problem>;
  } catch {
    body.detail = response.statusText || '服务器返回了无法解析的错误';
  }
  return new APIError({
    status: response.status,
    code: body.code ?? 'request_failed',
    detail: body.detail ?? body.title ?? '请求失败',
    title: body.title,
    type: body.type,
    request_id: body.request_id ?? response.headers.get('X-Request-ID') ?? undefined,
  });
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
  idempotent?: boolean;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json, application/problem+json');
  const csrf = localStorage.getItem(CSRF_STORAGE_KEY);
  if (isUnsafe(method) && csrf) headers.set('X-CSRF-Token', csrf);
  if (options.idempotent) headers.set('Idempotency-Key', crypto.randomUUID());
  let body: BodyInit | undefined;
  if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(options.body);
  }
  const response = await fetch(path, {
    ...options,
    method,
    headers,
    body,
    credentials: 'include',
    cache: 'no-store',
  });
  if (!response.ok) {
    const error = await parseError(response);
    if (error.status === 401) window.dispatchEvent(new Event('pki:unauthorized'));
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function requestList<T>(path: string): Promise<ListResponse<T>> {
  const response = await request<{ items?: T[] | null }>(path);
  return { items: Array.isArray(response.items) ? response.items : [] };
}

async function download(path: string, filename: string, method = 'GET', body?: unknown): Promise<void> {
  const headers = new Headers({ Accept: 'application/x-pem-file, application/octet-stream' });
  const csrf = localStorage.getItem(CSRF_STORAGE_KEY);
  if (isUnsafe(method) && csrf) headers.set('X-CSRF-Token', csrf);
  let payload: BodyInit | undefined;
  if (body !== undefined) {
    headers.set('Content-Type', 'application/json');
    payload = JSON.stringify(body);
  }
  const response = await fetch(path, { method, headers, body: payload, credentials: 'include', cache: 'no-store' });
  if (!response.ok) throw await parseError(response);
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export interface CreateCAInput {
  name: string;
  slug: string;
  parent_ca_id?: string;
  path_length: number;
  subject: Subject;
}

export interface ImportCAInput {
  name: string;
  slug: string;
  kind: 'root' | 'intermediate';
  parent_ca_id?: string;
  certificate_pem: string;
  private_key_pem: string;
}

export interface SigningProfileInput {
  name: string;
  description: string;
  default_validity_seconds: number;
  max_validity_seconds: number;
  key_usages: string[];
  extended_key_usages: string[];
  allowed_dns_patterns: string[];
  allowed_ip_ranges: string[];
  allow_email_sans: boolean;
  allow_uri_sans: boolean;
  policy: Record<string, unknown>;
  enabled: boolean;
}

export interface CreateRequestInput {
  ca_id: string;
  profile_id?: string;
  csr_pem?: string;
  subject: Subject;
  sans: string[];
  server_generate_key: boolean;
  requested_validity_seconds?: number;
}

export interface CreateTimestampAuthorityInput {
  slug: string;
  name: string;
  policy_oid: string;
  validity_seconds?: number;
}

export const consoleAPI = {
  login: async (input: { login: string; password: string; totp?: string }) => {
    const result = await request<LoginResponse>(`${consoleBase}/auth/login`, { method: 'POST', body: input });
    setCSRFToken(result.csrf_token);
    return result;
  },
  logout: async () => {
    await request<void>(`${consoleBase}/auth/logout`, { method: 'POST' });
    setCSRFToken();
  },
  session: () => request<{ user: User }>(`${consoleBase}/auth/session`),
  version: () => request<VersionInfo>(`${consoleBase}/version`),
  users: () => request<ListResponse<User>>(`${consoleBase}/users`),
  createUser: (input: { username: string; email?: string; role: 'operator' | 'user'; password: string }) =>
    request<User>(`${consoleBase}/users`, { method: 'POST', body: input, idempotent: true }),
  setUserStatus: (id: string, status: 'active' | 'disabled') =>
    request<void>(`${consoleBase}/users/${id}/status`, { method: 'PATCH', body: { status }, idempotent: true }),
  resetPassword: (id: string, password: string) =>
    request<void>(`${consoleBase}/users/${id}/password`, { method: 'PUT', body: { password }, idempotent: true }),
  authorities: () => request<ListResponse<CertificateAuthority>>(`${consoleBase}/cas`),
  authority: (id: string) => request<CertificateAuthority>(`${consoleBase}/cas/${id}`),
  createRoot: (input: CreateCAInput) =>
    request<CertificateAuthority>(`${consoleBase}/cas/roots`, { method: 'POST', body: input, idempotent: true }),
  createIntermediate: (input: CreateCAInput) =>
    request<CertificateAuthority>(`${consoleBase}/cas/intermediates`, { method: 'POST', body: input, idempotent: true }),
  importCA: (input: ImportCAInput) =>
    request<CertificateAuthority>(`${consoleBase}/cas/import`, { method: 'POST', body: input, idempotent: true }),
  exportCAKey: (id: string, password: string, totp: string) =>
    download(`${consoleBase}/cas/${id}/keys/export`, `${id}-ca-private-key.pem`, 'POST', { password, totp }),
  profiles: (caID: string) => requestList<SigningProfile>(`${consoleBase}/cas/${caID}/profiles`),
  createProfile: (caID: string, input: SigningProfileInput) =>
    request<SigningProfile>(`${consoleBase}/cas/${caID}/profiles`, { method: 'POST', body: input, idempotent: true }),
  updateProfile: (caID: string, profileID: string, input: SigningProfileInput) =>
    request<SigningProfile>(`${consoleBase}/cas/${caID}/profiles/${profileID}`, {
      method: 'PUT', body: input, idempotent: true,
    }),
  deleteProfile: (caID: string, profileID: string) =>
    request<void>(`${consoleBase}/cas/${caID}/profiles/${profileID}`, { method: 'DELETE', idempotent: true }),
  timestampAuthorities: (caID: string) =>
    requestList<TimestampAuthority>(`${consoleBase}/cas/${caID}/timestamp-authorities`),
  createTimestampAuthority: (caID: string, input: CreateTimestampAuthorityInput) =>
    request<TimestampAuthority>(`${consoleBase}/cas/${caID}/timestamp-authorities`, {
      method: 'POST', body: input, idempotent: true,
    }),
  grants: (caID: string) => request<ListResponse<CAGrant>>(`${consoleBase}/cas/${caID}/grants`),
  createGrant: (caID: string, userID: string, permission: CAGrant['permission']) =>
    request<void>(`${consoleBase}/cas/${caID}/grants`, {
      method: 'POST', body: { user_id: userID, permission }, idempotent: true,
    }),
  deleteGrant: (caID: string, userID: string, permission: string) =>
    request<void>(`${consoleBase}/cas/${caID}/grants/${userID}/${permission}`, {
      method: 'DELETE', idempotent: true,
    }),
  requests: () => request<ListResponse<CertificateRequest>>(`${consoleBase}/certificate-requests`),
  request: (id: string) => request<CertificateRequest>(`${consoleBase}/certificate-requests/${id}`),
  createRequest: (input: CreateRequestInput) =>
    request<CertificateRequest>(`${consoleBase}/certificate-requests`, { method: 'POST', body: input, idempotent: true }),
  decideRequest: (id: string, decision: 'approve' | 'reject', comment: string) =>
    request<{ id: string; status: string }>(`${consoleBase}/certificate-requests/${id}/${decision}`, {
      method: 'POST', body: { comment }, idempotent: true,
    }),
  certificates: () => request<ListResponse<Certificate>>(`${consoleBase}/certificates`),
  certificateInventory: (status?: CertificateInventoryStatus) =>
    request<ListResponse<CertificateInventoryItem>>(
      `${consoleBase}/certificate-inventory${status ? `?status=${encodeURIComponent(status)}` : ''}`,
    ),
  certificate: (id: string) => request<Certificate>(`${consoleBase}/certificates/${id}`),
  downloadCertificate: (id: string) => download(`${consoleBase}/certificates/${id}/download`, `${id}-chain.pem`),
  downloadPrivateKey: (id: string) =>
    download(`${consoleBase}/certificates/${id}/private-key/download`, `${id}-private-key.pem`, 'POST'),
  revokeCertificate: (id: string, reason: number, comment: string) =>
    request<Certificate>(`${consoleBase}/certificates/${id}/revoke`, {
      method: 'POST', body: { reason, comment }, idempotent: true,
    }),
  auditEvents: (limit = 100) => request<ListResponse<AuditRecord>>(`${consoleBase}/audit-events?limit=${limit}`),
  certInfo: (certificate_pem: string) =>
    request<Record<string, unknown>>(`${consoleBase}/utilities/certinfo`, { method: 'POST', body: { certificate_pem } }),
  generateCSR: (input: { subject: Subject; sans: string[]; algorithm: string; key_size: number }) =>
    request<{ csr_pem: string; private_key_pem: string }>(`${consoleBase}/utilities/csr`, { method: 'POST', body: input }),
  bundle: (input: { certificates_pem: string; roots_pem: string; intermediates_pem: string; flavor: string }) =>
    request<Record<string, unknown>>(`${consoleBase}/utilities/bundle`, { method: 'POST', body: input }),
};

export const publicAPI = {
  authorities: () => request<ListResponse<CertificateAuthority>>('/pki/v1/authorities'),
  byFingerprint: (fingerprint: string) =>
    request<Certificate>(`/pki/v1/certificates/by-fingerprint/${encodeURIComponent(fingerprint)}`),
  bySerial: (issuer: string, serial: string) =>
    request<Certificate>(`/pki/v1/certificates/by-issuer/${encodeURIComponent(issuer)}/serial/${encodeURIComponent(serial)}`),
  status: (issuer: string, serial: string) =>
    request<CertificateStatus>(`/pki/v1/status/${encodeURIComponent(issuer)}/${encodeURIComponent(serial)}`),
};
