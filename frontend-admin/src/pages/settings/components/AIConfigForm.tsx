import { Alert, Card, Form, Input, Switch, Typography } from 'antd'

import type { OpenAISettings } from '@/types/settings'

type AIConfigFormProps = {
  value: OpenAISettings
  onChange: (value: OpenAISettings) => void
}

export default function AIConfigForm({ value, onChange }: AIConfigFormProps) {
  return (
    <Card title="AI 配置" bordered={false}>
      <Typography.Paragraph type="secondary" style={{ marginTop: -8 }}>
        仅保存当前模型接入信息，不影响其他系统配置。
      </Typography.Paragraph>

      <Form layout="vertical">
        <Form.Item label="启用 AI 辅助检测" valuePropName="checked">
          <Switch
            checked={value.enabled}
            onChange={(checked) =>
              onChange({
                ...value,
                enabled: checked,
              })
            }
          />
        </Form.Item>

        <Form.Item label="API Key">
          <Input.Password
            value={value.api_key}
            onChange={(event) =>
              onChange({
                ...value,
                api_key: event.target.value,
              })
            }
            placeholder="sk-..."
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item label="Base URL">
          <Input
            value={value.base_url}
            onChange={(event) =>
              onChange({
                ...value,
                base_url: event.target.value,
              })
            }
            placeholder="https://api.openai.com/v1"
          />
        </Form.Item>

        <Form.Item
          label="模型"
          extra="例如 qwen-plus、gpt-4o-mini、deepseek-chat。"
        >
          <Input
            value={value.model}
            onChange={(event) =>
              onChange({
                ...value,
                model: event.target.value,
              })
            }
            placeholder="输入模型名称"
          />
        </Form.Item>
      </Form>

      <Alert
        type="info"
        showIcon
        message="提示"
        description="启用后，后端会在敏感信息与上传类检测流程中使用当前模型配置。"
      />
    </Card>
  )
}

