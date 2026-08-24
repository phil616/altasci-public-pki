import { describe, expect, it } from 'vitest';

import { can } from './permissions';

describe('role capabilities', () => {
  it('keeps root-only capabilities unavailable to operators', () => {
    expect(can('super_admin', 'create_ca')).toBe(true);
    expect(can('operator', 'create_ca')).toBe(false);
    expect(can('operator', 'decide_requests')).toBe(true);
  });

  it('keeps ordinary users in request-only workflows', () => {
    expect(can('user', 'read_audit')).toBe(false);
    expect(can('user', 'revoke_certificates')).toBe(false);
  });
});
