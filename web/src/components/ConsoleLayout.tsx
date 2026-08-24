import {
  AuditOutlined,
  BankOutlined,
  DownOutlined,
  DashboardOutlined,
  FileProtectOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  MoonOutlined,
  SafetyCertificateFilled,
  SunOutlined,
  TeamOutlined,
  ToolOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Avatar, Button, Drawer, Dropdown, Flex, Grid, Layout, Menu, Space, Typography } from 'antd';
import { useMemo, useState, type ReactNode } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/auth';
import { can } from '@/lib/permissions';
import { roleLabels } from '@/lib/format';
import { useColorMode } from '@/theme';

const { Header, Content, Sider } = Layout;
const { Text } = Typography;

interface NavItem { key: string; label: string; icon: ReactNode; visible?: boolean }

export function ConsoleLayout() {
  const { user, logout } = useAuth();
  const { mode, toggle } = useColorMode();
  const navigate = useNavigate();
  const location = useLocation();
  const screens = Grid.useBreakpoint();
  const mobile = !screens.lg;
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const items = useMemo<NavItem[]>(() => [
    { key: '/', label: '控制台', icon: <DashboardOutlined /> },
    { key: '/authorities', label: '证书机构', icon: <BankOutlined /> },
    { key: '/requests', label: '证书申请', icon: <FileProtectOutlined /> },
    { key: '/certificates', label: '证书库', icon: <SafetyCertificateFilled /> },
    { key: '/users', label: '用户管理', icon: <TeamOutlined />, visible: can(user?.role, 'manage_users') },
    { key: '/audit', label: '审计日志', icon: <AuditOutlined />, visible: can(user?.role, 'read_audit') },
    { key: '/utilities', label: 'PKI 工具', icon: <ToolOutlined /> },
  ].filter((item) => item.visible !== false), [user?.role]);

  const menu = (
    <Menu
      theme="dark"
      mode="inline"
      selectedKeys={[items.find((item) => item.key !== '/' && location.pathname.startsWith(item.key))?.key ?? '/']}
      items={items.map(({ key, label, icon }) => ({ key, label, icon }))}
      onClick={({ key }) => { void navigate(key); setDrawerOpen(false); }}
    />
  );

  const brand = (
    <Flex className="console-brand" align="center" gap="small">
      <div className="brand-mark"><SafetyCertificateFilled /></div>
      {collapsed && !mobile ? null : <div className="brand-name">PKI-Console</div>}
    </Flex>
  );

  return (
    <Layout className="console-shell">
      {!mobile ? (
        <Sider width={248} collapsedWidth={80} collapsed={collapsed} className="console-sider">
          {brand}
          <div className="nav-section-label">{collapsed ? '—' : '导航'}</div>
          {menu}
        </Sider>
      ) : (
        <Drawer open={drawerOpen} onClose={() => setDrawerOpen(false)} placement="left" size={280} styles={{ body: { padding: 0, background: '#07151c' }, header: { background: '#07151c', border: 0 } }} title={brand}>
          {menu}
        </Drawer>
      )}
      <Layout>
        <Header className="console-header">
          <Flex align="center" justify="space-between">
            <Button
              type="text"
              aria-label="切换导航"
              icon={mobile ? <MenuUnfoldOutlined /> : collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => mobile ? setDrawerOpen(true) : setCollapsed((value) => !value)}
            />
            <Space size="middle">
              <Button type="text" aria-label="切换颜色模式" icon={mode === 'dark' ? <SunOutlined /> : <MoonOutlined />} onClick={toggle} />
              <Dropdown trigger={['click']} placement="bottomRight" menu={{ items: [
                { key: 'identity', label: user?.email ?? user?.username, icon: <UserOutlined />, disabled: true },
                { type: 'divider' },
                { key: 'logout', label: '退出登录', icon: <LogoutOutlined />, danger: true, onClick: () => void logout().then(() => navigate('/login')) },
              ] }}>
                <Button type="text" className="identity-button">
                  <Avatar size={26} icon={<UserOutlined />} />
                  {!mobile ? <span className="identity-copy"><Text className="identity-name">{user?.username}</Text><Text type="secondary" className="identity-role">{user ? roleLabels[user.role] : ''}</Text></span> : null}
                  <DownOutlined className="identity-arrow" />
                </Button>
              </Dropdown>
            </Space>
          </Flex>
        </Header>
        <Content className="console-content"><Outlet /></Content>
      </Layout>
    </Layout>
  );
}
