export type Role = 'super_admin' | 'operator' | 'user';
export type UserStatus = 'active' | 'disabled' | 'locked';

export interface User {
  id: string;
  username: string;
  email?: string | null;
  role: Role;
  status: UserStatus;
  created_at?: string;
  updated_at?: string;
}

export interface LoginResponse {
  user: User;
  csrf_token: string;
  expires_at: string;
}

export interface Problem {
  type?: string;
  title?: string;
  status: number;
  detail: string;
  code: string;
  request_id?: string;
}

export interface Subject {
  common_name: string;
  country?: string;
  province?: string;
  locality?: string;
  organization?: string;
  organizational_unit?: string;
}

export interface CertificateAuthority {
  id: string;
  parent_ca_id?: string | null;
  slug: string;
  name: string;
  kind: 'root' | 'intermediate';
  status: string;
  subject: Subject;
  serial: string;
  certificate_pem: string;
  chain_pem: string;
  not_before: string;
  not_after: string;
  path_length: number;
  crl_url?: string | null;
  ocsp_url?: string | null;
  issuer_url?: string | null;
  created_by: string;
  created_at: string;
}

export interface SigningProfile {
  id: string;
  ca_id: string;
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

export interface CAGrant {
  ca_id: string;
  user_id: string;
  permission: 'view_requests' | 'approve' | 'issue' | 'revoke';
  granted_by: string;
  created_at: string;
}

export type RequestStatus =
  | 'pending'
  | 'approved'
  | 'issuing'
  | 'issued'
  | 'rejected'
  | 'failed'
  | 'cancelled';

export interface CertificateRequest {
  id: string;
  requester_id: string;
  ca_id: string;
  profile_id: string;
  csr_pem?: string;
  requested_subject: Subject;
  requested_sans: string[];
  key_generation_mode: 'client_csr' | 'server_generated';
  requested_validity_seconds?: number;
  status: RequestStatus;
  rejection_reason?: string;
  error_code?: string;
  submitted_at: string;
  approved_at?: string;
  issued_at?: string;
}

export interface Certificate {
  id: string;
  issuer_ca_id: string;
  owner_user_id: string;
  request_id?: string | null;
  serial: string;
  fingerprint_sha256: string;
  certificate_pem: string;
  chain_pem: string;
  subject: Subject;
  sans: string[];
  not_before: string;
  not_after: string;
  status: 'good' | 'revoked';
  created_at: string;
}

export type CertificateInventoryStatus = 'pending' | 'issued' | 'rejected' | 'failed';

export interface CertificateInventoryItem {
  request_id?: string | null;
  certificate_id?: string | null;
  owner_user_id: string;
  requester_username: string;
  issuer_ca_id: string;
  issuer_name: string;
  issuer_slug: string;
  subject: Subject;
  sans: string[];
  workflow_status: CertificateInventoryStatus;
  request_status?: RequestStatus | null;
  certificate_status?: 'good' | 'revoked' | null;
  serial?: string | null;
  rejection_reason?: string | null;
  error_code?: string | null;
  approver_id?: string | null;
  approver_username?: string | null;
  submitted_at: string;
  approved_at?: string | null;
  issued_at?: string | null;
  not_before?: string | null;
  not_after?: string | null;
}

export interface AuditRecord {
  id: string;
  actor_user_id?: string;
  actor_role?: Role;
  session_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  outcome: 'success' | 'denied' | 'failure';
  request_id: string;
  source_ip?: string;
  user_agent: string;
  cf_access_sub?: string;
  before_state?: unknown;
  after_state?: unknown;
  metadata?: unknown;
  previous_hash: string;
  event_hash: string;
  occurred_at: string;
}

export interface CertificateStatus {
  issuer: string;
  serial: string;
  status: 'good' | 'revoked' | 'expired';
  not_before: string;
  not_after: string;
}

export interface VersionInfo {
  name: string;
  version: string;
  cfssl_upstream: string;
}

export type ListResponse<T> = { items: T[] };
