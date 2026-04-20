import { Alert, Button, Card, Descriptions, Space, Tag, Typography } from 'antd'

import type { SystemStatus } from '@/types/settings'

type SystemStatusPanelProps = {
  value: SystemStatus
  loading?: boolean
  onRefresh: () => void
}

export default function SystemStatusPanel({
  value,
  loading,
  onRefresh,
}: SystemStatusPanelProps) {
  return (
    <Card
      title="系统状态"
      bordered={false}
      extra={
        <Button onClick={onRefresh} loading={loading}>
          检查连接
        </Button>
      }
    >
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label="Elasticsearch">
            <Tag color={value.connected ? 'green' : 'red'}>
              {value.connected ? '已连接' : '未连接'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="状态说明">
            <Typography.Text>{value.message || '未检查'}</Typography.Text>
          </Descriptions.Item>
        </Descriptions>

        {!value.connected && value.error ? (
          <Alert
            type="warning"
            showIcon
            message="Elasticsearch 连接异常"
            description={value.error}
          />
        ) : null}

        <Typography.Text type="secondary">
          该检查仅用于验证后端 Elasticsearch 连通性，不会修改配置。
        </Typography.Text>
      </Space>
    </Card>
  )
}

