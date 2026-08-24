import type { Role } from '@/types';

export const roleLabels: Record<Role, string> = {
  super_admin: '超级管理员',
  operator: '运维人员',
  user: '普通用户',
};

export function formatDate(value?: string | null): string {
  if (!value) return '—';
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

export function formatDuration(seconds: number): string {
  const days = seconds / 86400;
  if (Number.isInteger(days)) return `${days} 天`;
  const hours = seconds / 3600;
  if (Number.isInteger(hours)) return `${hours} 小时`;
  return `${seconds} 秒`;
}

export function shortID(value?: string | null, size = 8): string {
  if (!value) return '—';
  return value.length <= size * 2 ? value : `${value.slice(0, size)}…${value.slice(-size)}`;
}

export function downloadText(content: string, filename: string, type = 'application/x-pem-file'): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function copyText(value: string): Promise<void> {
  return navigator.clipboard.writeText(value);
}
