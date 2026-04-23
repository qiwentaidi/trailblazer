import { Button, Card, Col, Input, Row, Space, Tag, Typography } from 'antd'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { useState } from 'react'

type BasicConfigPanelProps = {
  value: {
    blackDomain: string[]
    highRiskRouter: string[]
    authentication: string[]
    learnedAuthentication: string[]
    placeholder: Record<string, string>
  }
  onChange: (value: BasicConfigPanelProps['value']) => void
}

type ListEditorCardProps = {
  title: string
  description: string
  placeholder: string
  items: string[]
  inputValue: string
  onInputChange: (value: string) => void
  onAdd: () => void
  onRemove: (index: number) => void
}

function ListEditorCard({
  title,
  description,
  placeholder,
  items,
  inputValue,
  onInputChange,
  onAdd,
  onRemove,
}: ListEditorCardProps) {
  return (
    <Card size="small" title={title}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Typography.Text type="secondary">{description}</Typography.Text>
        <Space.Compact style={{ width: '100%' }}>
          <Input
            value={inputValue}
            placeholder={placeholder}
            onChange={(event) => onInputChange(event.target.value)}
            onPressEnter={onAdd}
          />
          <Button type="primary" icon={<PlusOutlined />} onClick={onAdd}>
            添加
          </Button>
        </Space.Compact>
        <Space wrap>
          {items.map((item, index) => (
            <Tag
              key={`${title}-${item}-${index}`}
              closable
              onClose={(event) => {
                event.preventDefault()
                onRemove(index)
              }}
            >
              {item}
            </Tag>
          ))}
          {items.length === 0 ? <Typography.Text type="secondary">暂无配置</Typography.Text> : null}
        </Space>
      </Space>
    </Card>
  )
}

export default function BasicConfigPanel({ value, onChange }: BasicConfigPanelProps) {
  const [newDomain, setNewDomain] = useState('')
  const [newRoute, setNewRoute] = useState('')
  const [newAuthPattern, setNewAuthPattern] = useState('')
  const [newPlaceholderKey, setNewPlaceholderKey] = useState('')
  const [newPlaceholderValue, setNewPlaceholderValue] = useState('')

  const addListItem = (field: 'blackDomain' | 'highRiskRouter' | 'authentication', nextValue: string) => {
    const trimmed = nextValue.trim()
    if (!trimmed) {
      return
    }

    onChange({
      ...value,
      [field]: [...value[field], trimmed],
    })
  }

  const removeListItem = (field: 'blackDomain' | 'highRiskRouter' | 'authentication', index: number) => {
    onChange({
      ...value,
      [field]: value[field].filter((_, itemIndex) => itemIndex !== index),
    })
  }

  const addPlaceholder = () => {
    const key = newPlaceholderKey.trim()
    const nextValue = newPlaceholderValue.trim()
    if (!key || !nextValue) {
      return
    }

    onChange({
      ...value,
      placeholder: {
        ...value.placeholder,
        [key]: nextValue,
      },
    })
    setNewPlaceholderKey('')
    setNewPlaceholderValue('')
  }

  const removePlaceholder = (key: string) => {
    const nextPlaceholder = { ...value.placeholder }
    delete nextPlaceholder[key]
    onChange({
      ...value,
      placeholder: nextPlaceholder,
    })
  }

  return (
    <Card title="基础配置" bordered={false}>
      <Typography.Paragraph type="secondary" style={{ marginTop: -8 }}>
        这里保留旧版设置页中的基础规则配置，便于继续维护域名、路由、鉴权模式和占位符映射。
      </Typography.Paragraph>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <ListEditorCard
            title="黑名单域名"
            description="命中这些域名的目标将被排除在扫描范围外。"
            placeholder="输入域名，例如: example.com"
            items={value.blackDomain}
            inputValue={newDomain}
            onInputChange={setNewDomain}
            onAdd={() => {
              addListItem('blackDomain', newDomain)
              setNewDomain('')
            }}
            onRemove={(index) => removeListItem('blackDomain', index)}
          />
        </Col>
        <Col xs={24} xl={12}>
          <ListEditorCard
            title="高危路由"
            description="用于标记需要重点关注的敏感路径或动作。"
            placeholder="输入路由名称，例如: logout"
            items={value.highRiskRouter}
            inputValue={newRoute}
            onInputChange={setNewRoute}
            onAdd={() => {
              addListItem('highRiskRouter', newRoute)
              setNewRoute('')
            }}
            onRemove={(index) => removeListItem('highRiskRouter', index)}
          />
        </Col>
        <Col xs={24} xl={12}>
          <ListEditorCard
            title="鉴权模式"
            description="用于识别常见未授权或鉴权失败响应特征。"
            placeholder="输入鉴权模式，例如: Unauthorized"
            items={value.authentication}
            inputValue={newAuthPattern}
            onInputChange={setNewAuthPattern}
            onAdd={() => {
              addListItem('authentication', newAuthPattern)
              setNewAuthPattern('')
            }}
            onRemove={(index) => removeListItem('authentication', index)}
          />
        </Col>
        <Col xs={24} xl={12}>
          <Card size="small" title="自动学习的鉴权词组">
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Typography.Text type="secondary">
                这里展示后端运行过程中自动学习到的鉴权拦截短语，实时生效，仅展示不参与当前页面保存。
              </Typography.Text>
              <Space wrap>
                {value.learnedAuthentication.map((item, index) => (
                  <Tag key={`learned-auth-${item}-${index}`} color="gold">
                    {item}
                  </Tag>
                ))}
                {value.learnedAuthentication.length === 0 ? (
                  <Typography.Text type="secondary">暂无自动学习结果</Typography.Text>
                ) : null}
              </Space>
            </Space>
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card size="small" title="占位符">
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Typography.Text type="secondary">
                用于维护通用参数的占位值映射，例如 id 对应 1。
              </Typography.Text>
              <Space.Compact style={{ width: '100%' }}>
                <Input
                  value={newPlaceholderKey}
                  placeholder="键名关键词，例如: id"
                  onChange={(event) => setNewPlaceholderKey(event.target.value)}
                />
                <Input
                  value={newPlaceholderValue}
                  placeholder="值，例如: 1"
                  onChange={(event) => setNewPlaceholderValue(event.target.value)}
                  onPressEnter={addPlaceholder}
                />
                <Button type="primary" icon={<PlusOutlined />} onClick={addPlaceholder}>
                  添加
                </Button>
              </Space.Compact>
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                {Object.entries(value.placeholder).map(([key, itemValue]) => (
                  <Card
                    key={key}
                    size="small"
                    bodyStyle={{ padding: 12 }}
                  >
                    <Space style={{ justifyContent: 'space-between', width: '100%' }}>
                      <Typography.Text>
                        <Typography.Text strong>{key}</Typography.Text>
                        {' -> '}
                        {itemValue}
                      </Typography.Text>
                      <Button
                        type="text"
                        danger
                        icon={<DeleteOutlined />}
                        onClick={() => removePlaceholder(key)}
                      >
                        删除
                      </Button>
                    </Space>
                  </Card>
                ))}
                {Object.keys(value.placeholder).length === 0 ? (
                  <Typography.Text type="secondary">暂无配置</Typography.Text>
                ) : null}
              </Space>
            </Space>
          </Card>
        </Col>
      </Row>
    </Card>
  )
}
