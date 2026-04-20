import { Button, Card, Col, Collapse, Form, Input, InputNumber, Radio, Row, Select, Space, Switch, Tag, Typography } from 'antd'
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons'
import type { ReactNode } from 'react'
import { useState } from 'react'

import type {
  LFIPayloadRule,
  SQLiPayloadRule,
  VulnDetectionSettings,
  XSSPayloadRule,
} from '@/types/settings'

type VulnRulesPanelProps = {
  value: VulnDetectionSettings
  onChange: (value: VulnDetectionSettings) => void
}

const toLines = (items: string[]) => items.join('\n')

const fromLines = (text: string) =>
  text
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0)

const createSqlRule = (): SQLiPayloadRule => ({
  payloads: [],
  type: 'error-based',
  minDelayMs: 0,
  bodyContains: [],
})

const createLfiRule = (): LFIPayloadRule => ({
  payloads: [],
  matchType: 'regex',
  regex: [],
  words: [],
  condition: 'or',
})

const createXssRule = (): XSSPayloadRule => ({
  payloads: [],
  type: 'reflected',
  statusEquals: 0,
  headerContains: {},
  bodyContains: [],
})

function SectionCard({
  title,
  enabled,
  onToggle,
  children,
  description,
}: {
  title: string
  enabled: boolean
  onToggle: (checked: boolean) => void
  children: ReactNode
  description?: string
}) {
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <Space wrap style={{ justifyContent: 'space-between', width: '100%' }}>
        <Space wrap>
          <Switch checked={enabled} onChange={onToggle} />
          <Typography.Text strong>{title}</Typography.Text>
          <Tag color={enabled ? 'success' : 'default'}>{enabled ? '已启用' : '已关闭'}</Tag>
        </Space>
        {description ? <Typography.Text type="secondary">{description}</Typography.Text> : null}
      </Space>
      {children}
    </div>
  )
}

export default function VulnRulesPanel({ value, onChange }: VulnRulesPanelProps) {
  const [newLfiParam, setNewLfiParam] = useState('')
  const [newSsrfParam, setNewSsrfParam] = useState('')
  const [newRedirectParam, setNewRedirectParam] = useState('')

  const updateSection = <K extends keyof VulnDetectionSettings>(
    key: K,
    nextValue: VulnDetectionSettings[K],
  ) =>
    onChange({
      ...value,
      [key]: nextValue,
    })

  const updateSqlRule = (index: number, nextRule: SQLiPayloadRule) => {
    const rules = [...value.sqlInjection.rules]
    rules[index] = nextRule
    updateSection('sqlInjection', {
      ...value.sqlInjection,
      rules,
    })
  }

  const updateLfiRule = (index: number, nextRule: LFIPayloadRule) => {
    const rules = [...value.lfi.rules]
    rules[index] = nextRule
    updateSection('lfi', {
      ...value.lfi,
      rules,
    })
  }

  const updateXssRule = (index: number, nextRule: XSSPayloadRule) => {
    const rules = [...value.xss.rules]
    rules[index] = nextRule
    updateSection('xss', {
      ...value.xss,
      rules,
    })
  }

  const addTag = (
    key: 'paramKeywords',
    section: 'lfi' | 'ssrf' | 'redirect',
    rawValue: string,
    setRawValue: (value: string) => void,
  ) => {
    const next = rawValue.trim()
    if (!next) {
      return
    }

    updateSection(section, {
      ...value[section],
      [key]: [...value[section][key], next],
    } as VulnDetectionSettings[typeof section])
    setRawValue('')
  }

  return (
    <Card title="漏洞规则" bordered={false}>
      <Typography.Paragraph type="secondary" style={{ marginTop: -8 }}>
        当前只展示后端实际保存的漏洞检测规则，不包含弱口令等未纳入本次迁移的配置。
      </Typography.Paragraph>

      <Card
        size="small"
        style={{ marginBottom: 16 }}
        title="漏洞检测总开关"
      >
        <Space style={{ justifyContent: 'space-between', width: '100%' }}>
          <Typography.Text>
            关闭后将整体停用 SDK 漏洞检测链路，但会保留下面各项规则配置。
          </Typography.Text>
          <Switch
            checked={value.enabled}
            onChange={(checked) =>
              onChange({
                ...value,
                enabled: checked,
              })
            }
          />
        </Space>
      </Card>

      <div
        style={{
          opacity: value.enabled ? 1 : 0.55,
          pointerEvents: value.enabled ? 'auto' : 'none',
          transition: 'opacity 0.2s ease',
        }}
      >
        <Collapse
          defaultActiveKey={['sqlInjection']}
          size="middle"
          items={[
            {
              key: 'sqlInjection',
              label: 'SQL 注入检测',
              extra: <Tag color={value.sqlInjection.enabled ? 'success' : 'default'}>{value.sqlInjection.enabled ? '已启用' : '已关闭'}</Tag>,
              children: (
                <SectionCard
                  title="SQL 注入检测"
                  enabled={value.sqlInjection.enabled}
                  onToggle={(checked) =>
                    updateSection('sqlInjection', {
                      ...value.sqlInjection,
                      enabled: checked,
                    })
                  }
                  description="支持错误注入、时间注入等规则。"
                >
                  <Space direction="vertical" size={12} style={{ width: '100%' }}>
                    <Space direction="vertical" size={12} style={{ width: '100%' }}>
                      {value.sqlInjection.rules.map((rule, index) => (
                        <Card
                          key={`sql-rule-${index}`}
                          size="small"
                          title={`规则 ${index + 1}`}
                          extra={
                            <Button
                              danger
                              type="text"
                              icon={<DeleteOutlined />}
                              onClick={() =>
                                updateSection('sqlInjection', {
                                  ...value.sqlInjection,
                                  rules: value.sqlInjection.rules.filter((_, i) => i !== index),
                                })
                              }
                            >
                              删除
                            </Button>
                          }
                        >
                          <Row gutter={16}>
                            <Col span={24}>
                              <Form layout="vertical">
                                <Form.Item label="Payload 列表">
                                  <Input.TextArea
                                    value={toLines(rule.payloads)}
                                    onChange={(event) =>
                                      updateSqlRule(index, {
                                        ...rule,
                                        payloads: fromLines(event.target.value),
                                      })
                                    }
                                    rows={4}
                                    placeholder="每行一个 payload"
                                  />
                                </Form.Item>
                                <Form.Item label="检测类型">
                                  <Select
                                    value={rule.type}
                                    onChange={(nextType) =>
                                      updateSqlRule(index, {
                                        ...rule,
                                        type: nextType,
                                      })
                                    }
                                    options={[
                                      { label: 'Error-based', value: 'error-based' },
                                      { label: 'Time-based', value: 'time-based' },
                                      { label: 'Boolean-based', value: 'boolean-based' },
                                    ]}
                                  />
                                </Form.Item>
                                {rule.type === 'time-based' ? (
                                  <Form.Item label="最小延时（毫秒）">
                                    <InputNumber
                                      min={0}
                                      value={rule.minDelayMs}
                                      onChange={(nextDelay) =>
                                        updateSqlRule(index, {
                                          ...rule,
                                          minDelayMs: typeof nextDelay === 'number' ? nextDelay : 0,
                                        })
                                      }
                                      style={{ width: '100%' }}
                                    />
                                  </Form.Item>
                                ) : null}
                                <Form.Item label="响应体包含">
                                  <Input.TextArea
                                    value={toLines(rule.bodyContains)}
                                    onChange={(event) =>
                                      updateSqlRule(index, {
                                        ...rule,
                                        bodyContains: fromLines(event.target.value),
                                      })
                                    }
                                    rows={3}
                                    placeholder="每行一个关键词"
                                  />
                                </Form.Item>
                              </Form>
                            </Col>
                          </Row>
                        </Card>
                      ))}

                      <Button
                        type="dashed"
                        icon={<PlusOutlined />}
                        onClick={() =>
                          updateSection('sqlInjection', {
                            ...value.sqlInjection,
                            rules: [...value.sqlInjection.rules, createSqlRule()],
                          })
                        }
                      >
                        添加规则
                      </Button>
                    </Space>
                  </Space>
                </SectionCard>
              ),
            },
            {
              key: 'lfi',
              label: 'LFI 检测',
              extra: <Tag color={value.lfi.enabled ? 'success' : 'default'}>{value.lfi.enabled ? '已启用' : '已关闭'}</Tag>,
              children: (
                <SectionCard
                  title="LFI 检测"
                  enabled={value.lfi.enabled}
                  onToggle={(checked) =>
                    updateSection('lfi', {
                      ...value.lfi,
                      enabled: checked,
                    })
                  }
                  description="支持参数关键词与多条 payload / 命中规则。"
                >
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Form layout="vertical">
              <Form.Item label="参数关键词">
                <Space wrap style={{ width: '100%' }}>
                  {value.lfi.paramKeywords.map((item) => (
                    <Button
                      key={item}
                      onClick={() =>
                        updateSection('lfi', {
                          ...value.lfi,
                          paramKeywords: value.lfi.paramKeywords.filter((keyword) => keyword !== item),
                        })
                      }
                    >
                      {item}
                    </Button>
                  ))}
                </Space>
                <Space style={{ marginTop: 12, width: '100%' }}>
                  <Input
                    value={newLfiParam}
                    onChange={(event) => setNewLfiParam(event.target.value)}
                    placeholder="例如 file、path、filepath"
                    onPressEnter={() => addTag('paramKeywords', 'lfi', newLfiParam, setNewLfiParam)}
                  />
                  <Button
                    type="primary"
                    onClick={() => addTag('paramKeywords', 'lfi', newLfiParam, setNewLfiParam)}
                  >
                    添加
                  </Button>
                </Space>
              </Form.Item>
            </Form>

            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              {value.lfi.rules.map((rule, index) => (
                <Card
                  key={`lfi-rule-${index}`}
                  size="small"
                  title={`规则 ${index + 1}`}
                  extra={
                    <Button
                      danger
                      type="text"
                      icon={<DeleteOutlined />}
                      onClick={() =>
                        updateSection('lfi', {
                          ...value.lfi,
                          rules: value.lfi.rules.filter((_, i) => i !== index),
                        })
                      }
                    >
                      删除
                    </Button>
                  }
                >
                  <Form layout="vertical">
                    <Form.Item label="Payload 列表">
                      <Input.TextArea
                        value={toLines(rule.payloads)}
                        onChange={(event) =>
                          updateLfiRule(index, {
                            ...rule,
                            payloads: fromLines(event.target.value),
                          })
                        }
                        rows={4}
                      />
                    </Form.Item>
                    <Form.Item label="匹配类型">
                      <Select
                        value={rule.matchType}
                        onChange={(nextValue) =>
                          updateLfiRule(index, {
                            ...rule,
                            matchType: nextValue,
                          })
                        }
                        options={[
                          { label: 'Regex', value: 'regex' },
                          { label: 'Word', value: 'word' },
                        ]}
                      />
                    </Form.Item>
                    {rule.matchType === 'regex' ? (
                      <Form.Item label="正则表达式">
                        <Input.TextArea
                          value={toLines(rule.regex)}
                          onChange={(event) =>
                            updateLfiRule(index, {
                              ...rule,
                              regex: fromLines(event.target.value),
                            })
                          }
                          rows={3}
                        />
                      </Form.Item>
                    ) : null}
                    {rule.matchType === 'word' ? (
                      <>
                        <Form.Item label="关键词">
                          <Input.TextArea
                            value={toLines(rule.words)}
                            onChange={(event) =>
                              updateLfiRule(index, {
                                ...rule,
                                words: fromLines(event.target.value),
                              })
                            }
                            rows={3}
                          />
                        </Form.Item>
                        <Form.Item label="匹配条件">
                          <Radio.Group
                            value={rule.condition}
                            onChange={(event) =>
                              updateLfiRule(index, {
                                ...rule,
                                condition: event.target.value,
                              })
                            }
                          >
                            <Radio value="and">全部匹配</Radio>
                            <Radio value="or">任意匹配</Radio>
                          </Radio.Group>
                        </Form.Item>
                      </>
                    ) : null}
                  </Form>
                </Card>
              ))}

              <Button
                type="dashed"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateSection('lfi', {
                    ...value.lfi,
                    rules: [...value.lfi.rules, createLfiRule()],
                  })
                }
              >
                添加规则
              </Button>
            </Space>
          </Space>
                </SectionCard>
              ),
            },
            {
              key: 'ssrf',
              label: 'SSRF 检测',
              extra: <Tag color={value.ssrf.enabled ? 'success' : 'default'}>{value.ssrf.enabled ? '已启用' : '已关闭'}</Tag>,
              children: (
                <SectionCard
                  title="SSRF 检测"
                  enabled={value.ssrf.enabled}
                  onToggle={(checked) =>
                    updateSection('ssrf', {
                      ...value.ssrf,
                      enabled: checked,
                    })
                  }
                  description="通过参数关键词筛选可疑请求入口。"
                >
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Space wrap style={{ width: '100%' }}>
              {value.ssrf.paramKeywords.map((item) => (
                <Button
                  key={item}
                  onClick={() =>
                    updateSection('ssrf', {
                      ...value.ssrf,
                      paramKeywords: value.ssrf.paramKeywords.filter((keyword) => keyword !== item),
                    })
                  }
                >
                  {item}
                </Button>
              ))}
            </Space>
            <Space style={{ width: '100%' }}>
              <Input
                value={newSsrfParam}
                onChange={(event) => setNewSsrfParam(event.target.value)}
                placeholder="例如 url、link、src"
                onPressEnter={() => addTag('paramKeywords', 'ssrf', newSsrfParam, setNewSsrfParam)}
              />
              <Button
                type="primary"
                onClick={() => addTag('paramKeywords', 'ssrf', newSsrfParam, setNewSsrfParam)}
              >
                添加
              </Button>
            </Space>
          </Space>
                </SectionCard>
              ),
            },
            {
              key: 'redirect',
              label: '重定向检测',
              extra: <Tag color={value.redirect.enabled ? 'success' : 'default'}>{value.redirect.enabled ? '已启用' : '已关闭'}</Tag>,
              children: (
                <SectionCard
                  title="重定向检测"
                  enabled={value.redirect.enabled}
                  onToggle={(checked) =>
                    updateSection('redirect', {
                      ...value.redirect,
                      enabled: checked,
                    })
                  }
                  description="通过参数关键词识别开放重定向入口。"
                >
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Space wrap style={{ width: '100%' }}>
              {value.redirect.paramKeywords.map((item) => (
                <Button
                  key={item}
                  onClick={() =>
                    updateSection('redirect', {
                      ...value.redirect,
                      paramKeywords: value.redirect.paramKeywords.filter((keyword) => keyword !== item),
                    })
                  }
                >
                  {item}
                </Button>
              ))}
            </Space>
            <Space style={{ width: '100%' }}>
              <Input
                value={newRedirectParam}
                onChange={(event) => setNewRedirectParam(event.target.value)}
                placeholder="例如 url、redirect、next"
                onPressEnter={() => addTag('paramKeywords', 'redirect', newRedirectParam, setNewRedirectParam)}
              />
              <Button
                type="primary"
                onClick={() => addTag('paramKeywords', 'redirect', newRedirectParam, setNewRedirectParam)}
              >
                添加
              </Button>
            </Space>
          </Space>
                </SectionCard>
              ),
            },
            {
              key: 'xss',
              label: 'XSS 检测',
              extra: <Tag color={value.xss.enabled ? 'success' : 'default'}>{value.xss.enabled ? '已启用' : '已关闭'}</Tag>,
              children: (
                <SectionCard
                  title="XSS 检测"
                  enabled={value.xss.enabled}
                  onToggle={(checked) =>
                    updateSection('xss', {
                      ...value.xss,
                      enabled: checked,
                    })
                  }
                  description="保留后端支持的 reflected / dom-based 规则字段。"
                >
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              {value.xss.rules.map((rule, index) => (
                <Card
                  key={`xss-rule-${index}`}
                  size="small"
                  title={`规则 ${index + 1}`}
                  extra={
                    <Button
                      danger
                      type="text"
                      icon={<DeleteOutlined />}
                      onClick={() =>
                        updateSection('xss', {
                          ...value.xss,
                          rules: value.xss.rules.filter((_, i) => i !== index),
                        })
                      }
                    >
                      删除
                    </Button>
                  }
                >
                  <Form layout="vertical">
                    <Form.Item label="Payload 列表">
                      <Input.TextArea
                        value={toLines(rule.payloads)}
                        onChange={(event) =>
                          updateXssRule(index, {
                            ...rule,
                            payloads: fromLines(event.target.value),
                          })
                        }
                        rows={4}
                      />
                    </Form.Item>
                    <Form.Item label="检测类型">
                      <Select
                        value={rule.type}
                        onChange={(nextValue) =>
                          updateXssRule(index, {
                            ...rule,
                            type: nextValue,
                          })
                        }
                        options={[
                          { label: 'Reflected', value: 'reflected' },
                          { label: 'DOM-based', value: 'dom-based' },
                        ]}
                      />
                    </Form.Item>
                    <Form.Item label="期望状态码">
                      <InputNumber
                        min={0}
                        max={599}
                        value={rule.statusEquals}
                        onChange={(nextValue) =>
                          updateXssRule(index, {
                            ...rule,
                            statusEquals: typeof nextValue === 'number' ? nextValue : 0,
                          })
                        }
                        style={{ width: '100%' }}
                      />
                    </Form.Item>
                  </Form>
                </Card>
              ))}

              <Button
                type="dashed"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateSection('xss', {
                    ...value.xss,
                    rules: [...value.xss.rules, createXssRule()],
                  })
                }
              >
                添加规则
              </Button>
            </Space>
          </Space>
                </SectionCard>
              ),
            },
            {
              key: 'upload',
              label: '文件上传检测',
              extra: <Tag color={value.upload.enabled ? 'success' : 'default'}>{value.upload.enabled ? '已启用' : '已关闭'}</Tag>,
              children: (
                <SectionCard
                  title="文件上传检测"
                  enabled={value.upload.enabled}
                  onToggle={(checked) =>
                    updateSection('upload', {
                      ...value.upload,
                      enabled: checked,
                    })
                  }
                  description="仅用于上传接口的自动化验证。"
                >
          <Form layout="vertical">
            <Form.Item label="测试文件内容">
              <Input.TextArea
                value={value.upload.testContent}
                onChange={(event) =>
                  updateSection('upload', {
                    ...value.upload,
                    testContent: event.target.value,
                  })
                }
                rows={4}
              />
            </Form.Item>
            <Form.Item label="测试文件名">
              <Input
                value={value.upload.testFileName}
                onChange={(event) =>
                  updateSection('upload', {
                    ...value.upload,
                    testFileName: event.target.value,
                  })
                }
                placeholder="test.html"
              />
            </Form.Item>
          </Form>
                </SectionCard>
              ),
            },
          ]}
        />
      </div>
    </Card>
  )
}
