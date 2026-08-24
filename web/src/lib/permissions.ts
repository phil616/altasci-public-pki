import type { Role } from '@/types';

export type Capability =
  | 'manage_users'
  | 'create_ca'
  | 'manage_profiles'
  | 'manage_tsa'
  | 'manage_grants'
  | 'export_ca_key'
  | 'decide_requests'
  | 'revoke_certificates'
  | 'read_audit';

const capabilities: Record<Role, ReadonlySet<Capability>> = {
  super_admin: new Set([
    'manage_users',
    'create_ca',
    'manage_profiles',
    'manage_tsa',
    'manage_grants',
    'export_ca_key',
    'decide_requests',
    'revoke_certificates',
    'read_audit',
  ]),
  operator: new Set(['decide_requests', 'revoke_certificates']),
  user: new Set(),
};

export function can(role: Role | undefined, capability: Capability): boolean {
  return role ? capabilities[role].has(capability) : false;
}
