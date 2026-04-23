import {
  Button,
  Card,
  Collapse,
  message,
  Space,
  Spin,
  Tag,
  Typography,
} from 'antd';
import { useEffect, useState } from 'react';

import {
  checkEsHealth,
  createDefaultSettings,
  getSettings,
  saveSettings,
} from '@/services/settings';
import type { SettingsConfig, SystemStatus } from '@/types/settings';
import AIConfigForm from './components/AIConfigForm';
import BasicConfigPanel from './components/BasicConfigPanel';
import SystemStatusPanel from './components/SystemStatusPanel';
import VulnRulesPanel from './components/VulnRulesPanel';

export default function SettingsPage() {
  const [settings, setSettings] = useState<SettingsConfig>(
    createDefaultSettings(),
  );
  const [loading, setLoading] = useState(false);
  const [settingsInitialized, setSettingsInitialized] = useState(false);
  const [saving, setSaving] = useState(false);
  const [healthLoading, setHealthLoading] = useState(false);
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    connected: false,
    message: '未检查',
  });

  const loadSettings = async () => {
    setLoading(true);
    try {
      const nextSettings = await getSettings();
      setSettings(nextSettings);
      setSettingsInitialized(true);
    } catch {
      setSettingsInitialized(false);
      message.error('加载配置失败');
    } finally {
      setLoading(false);
    }
  };

  const loadSystemStatus = async () => {
    setHealthLoading(true);
    try {
      const nextStatus = await checkEsHealth();
      setSystemStatus(nextStatus);
    } catch {
      setSystemStatus({
        connected: false,
        message: '检查失败',
        error: '网络请求失败',
      });
      message.error('检查连接失败');
    } finally {
      setHealthLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await saveSettings(settings);
      message.success('配置已保存');
    } catch {
      message.error('保存配置失败');
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    void loadSettings();
    void loadSystemStatus();
  }, []);

  return (
    <Card
      title="配置中心"
      bordered={false}
      extra={
        <Space>
          <Button onClick={() => void loadSettings()} loading={loading}>
            刷新配置
          </Button>
          <Button
            type="primary"
            onClick={() => void handleSave()}
            loading={saving}
            disabled={!settingsInitialized || loading}
          >
            保存配置
          </Button>
        </Space>
      }
    >
      <Typography.Paragraph type="secondary" style={{ marginTop: -8 }}>
        当前页已补齐旧版基础配置、AI
        配置、漏洞规则和系统状态检查，保存行为保持不变。
      </Typography.Paragraph>

      <Spin spinning={loading}>
        <Collapse
          defaultActiveKey={['basic', 'ai', 'vuln']}
          size="large"
          items={[
            {
              key: 'basic',
              label: (
                <Space wrap>
                  <Typography.Text strong>基础配置</Typography.Text>
                  <Tag color="blue">
                    {settings.blackDomain.length +
                      settings.highRiskRouter.length +
                      settings.authentication.length +
                      settings.learnedAuthentication.length +
                      Object.keys(settings.placeholder).length}{' '}
                    项
                  </Tag>
                </Space>
              ),
              children: (
                <BasicConfigPanel
                  value={{
                    blackDomain: settings.blackDomain,
                    highRiskRouter: settings.highRiskRouter,
                    authentication: settings.authentication,
                    learnedAuthentication: settings.learnedAuthentication,
                    placeholder: settings.placeholder,
                  }}
                  onChange={(basicSettings) =>
                    setSettings((current) => ({
                      ...current,
                      blackDomain: basicSettings.blackDomain,
                      highRiskRouter: basicSettings.highRiskRouter,
                      authentication: basicSettings.authentication,
                      learnedAuthentication:
                        basicSettings.learnedAuthentication,
                      placeholder: basicSettings.placeholder,
                    }))
                  }
                />
              ),
            },
            {
              key: 'ai',
              label: (
                <Space wrap>
                  <Typography.Text strong>AI 配置</Typography.Text>
                  <Tag color={settings.openai.enabled ? 'success' : 'default'}>
                    {settings.openai.enabled ? '已启用' : '已关闭'}
                  </Tag>
                </Space>
              ),
              children: (
                <AIConfigForm
                  value={settings.openai}
                  onChange={(openai) =>
                    setSettings((current) => ({
                      ...current,
                      openai,
                    }))
                  }
                />
              ),
            },
            {
              key: 'vuln',
              label: (
                <Space wrap>
                  <Typography.Text strong>漏洞规则</Typography.Text>
                  <Tag
                    color={
                      settings.vulnDetection.enabled ? 'processing' : 'default'
                    }
                  >
                    {settings.vulnDetection.enabled ? '检测开启' : '检测关闭'}
                  </Tag>
                </Space>
              ),
              children: (
                <VulnRulesPanel
                  value={settings.vulnDetection}
                  onChange={(vulnDetection) =>
                    setSettings((current) => ({
                      ...current,
                      vulnDetection,
                    }))
                  }
                />
              ),
            },
            {
              key: 'status',
              label: (
                <Space wrap>
                  <Typography.Text strong>系统状态</Typography.Text>
                  <Tag color={systemStatus.connected ? 'success' : 'error'}>
                    {systemStatus.connected ? 'ES 已连接' : 'ES 未连接'}
                  </Tag>
                </Space>
              ),
              children: (
                <SystemStatusPanel
                  value={systemStatus}
                  loading={healthLoading}
                  onRefresh={() => void loadSystemStatus()}
                />
              ),
            },
          ]}
        />
      </Spin>
    </Card>
  );
}
