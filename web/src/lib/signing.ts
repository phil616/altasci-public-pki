import { request } from '@/lib/api';

export interface IssuancePolicy {
  version: number;
  allowed_dns_names: string[];
  allowed_ip_ranges: string[];
  allowed_email_domains: string[];
  allowed_uri_prefixes: string[];
  allow_wildcards: boolean;
  extended_key_usages: string[];
  default_validity_seconds: number;
  max_validity_seconds: number;
  max_sans: number;
}
export interface SigningInstance {
  id: string; owner_id: string; name: string;
  certificate_pem: string; chain_pem: string; policy: IssuancePolicy;
  enabled: boolean; not_before: string; not_after: string; endpoint: string;
  created_at: string; updated_at: string;
}
export interface SigningCredential {
  id: string; instance_id: string; name: string; scopes: string[];
  policy: IssuancePolicy | null; max_issuances: number; issued_count: number;
  rate_per_minute: number; expires_at: string; revoked_at: string | null; created_at: string;
}
export interface IndependentCertificate {
  id: string; instance_id: string; credential_id: string; serial: string;
  certificate_pem: string; chain_pem: string; fingerprint_sha256: string;
  not_before: string; not_after: string; revoked_at: string | null;
  revocation_reason: number | null; status: string; created_at: string;
}
export interface SigningCreateInput { name: string; certificate_pem: string; private_key_pem: string; chain_pem: string; policy: IssuancePolicy }
export interface SigningCredentialInput { name: string; scopes: string[]; policy?: IssuancePolicy; lifetime_seconds: number; max_issuances: number; rate_per_minute: number }
export const defaultIssuancePolicy: IssuancePolicy = {
  version: 1, allowed_dns_names: [], allowed_ip_ranges: [], allowed_email_domains: [], allowed_uri_prefixes: [],
  allow_wildcards: false, extended_key_usages: ['server_auth'], default_validity_seconds: 2592000, max_validity_seconds: 7776000, max_sans: 32,
};
const base = '/api/v1/signing-instances';
export const signingAPI = {
  list: () => request<{ items: SigningInstance[] }>(base),
  get: (id: string) => request<SigningInstance>(`${base}/${id}`),
  create: (input: SigningCreateInput) => request<SigningInstance>(base, { method: 'POST', body: input }),
  update: (id: string, input: Pick<SigningInstance, 'name' | 'policy' | 'enabled'>) => request<SigningInstance>(`${base}/${id}`, { method: 'PUT', body: input, idempotent: true }),
  credentials: (id: string) => request<{ items: SigningCredential[] }>(`${base}/${id}/credentials`),
  createCredential: (id: string, input: SigningCredentialInput) => request<{ credential: SigningCredential; token: string }>(`${base}/${id}/credentials`, { method: 'POST', body: input }),
  revokeCredential: (id: string, credential: string) => request<void>(`${base}/${id}/credentials/${credential}/revoke`, { method: 'POST', idempotent: true }),
  certificates: (id: string, before: string) => request<{ items: IndependentCertificate[]; next_cursor: string }>(`${base}/${id}/certificates?before=${encodeURIComponent(before)}`),
  revoke: (id: string, certificate: string, reason: number) => request<IndependentCertificate>(`${base}/${id}/certificates/${certificate}/revoke`, { method: 'POST', body: { reason }, idempotent: true }),
};
