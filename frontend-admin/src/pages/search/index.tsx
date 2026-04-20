import {
  PlusOutlined,
  SearchOutlined,
} from '@ant-design/icons'
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Empty,
  Form,
  Input,
  List,
  Modal,
  Pagination,
  Row,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from 'antd'
import { useEffect, useMemo, useState } from 'react'

import {
  createSearchRule,
  deleteSearchRule,
  fetchSearchRules,
  searchJSContent,
  type SearchMatch,
  type SearchResult,
  type SearchRule,
} from '@/services/search'
import { useLocation } from 'umi'

const DEFAULT_FILE_PAGE_SIZE = 10

function buildHighlightedSegments(
  content: string,
  start: number,
  end: number,
  originalMatch?: string,
) {
  if (originalMatch && originalMatch.trim()) {
    const matchIndex = content.indexOf(originalMatch)
    if (matchIndex >= 0) {
      return {
        before: content.slice(0, matchIndex),
        match: content.slice(matchIndex, matchIndex + originalMatch.length),
        after: content.slice(matchIndex + originalMatch.length),
      }
    }
  }

  if (start < 0 || end > content.length || start >= end) {
    return {
      before: content,
      match: '',
      after: '',
    }
  }

  return {
    before: content.slice(0, start),
    match: content.slice(start, end),
    after: content.slice(end),
  }
}

function renderMatchContent(match: SearchMatch) {
  const segments = buildHighlightedSegments(
    match.content,
    match.matchStart,
    match.matchEnd,
    match.originalText,
  )

  return (
    <pre
      style={{
        margin: 0,
        padding: 12,
        background: '#f7f8fa',
        borderRadius: 8,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
        fontSize: 12,
        lineHeight: 1.6,
      }}
    >
      <span>{segments.before}</span>
      <span
        style={{
          background: '#fff3bf',
          color: '#ad4e00',
          fontWeight: 600,
          padding: '1px 2px',
          borderRadius: 4,
        }}
      >
        {segments.match}
      </span>
      <span>{segments.after}</span>
    </pre>
  )
}

export default function SearchPage() {
  const location = useLocation()
  const [pattern, setPattern] = useState('')
  const [isRegex, setIsRegex] = useState(true)
  const [caseSensitive, setCaseSensitive] = useState(false)
  const [searching, setSearching] = useState(false)
  const [searchCompleted, setSearchCompleted] = useState(false)
  const [rulesLoading, setRulesLoading] = useState(false)
  const [results, setResults] = useState<SearchResult[]>([])
  const [selectedResultId, setSelectedResultId] = useState<string>('')
  const [rules, setRules] = useState<SearchRule[]>([])
  const [saveOpen, setSaveOpen] = useState(false)
  const [filePage, setFilePage] = useState(1)
  const [filePageSize, setFilePageSize] = useState(DEFAULT_FILE_PAGE_SIZE)
  const [saveForm] = Form.useForm<{ label: string; value: string }>()

  const selectedResult = useMemo(
    () => results.find((item) => item.id === selectedResultId) || null,
    [results, selectedResultId],
  )

  const totalMatches = useMemo(
    () => results.reduce((sum, item) => sum + item.totalMatches, 0),
    [results],
  )

  const pagedResults = useMemo(() => {
    const startIndex = (filePage - 1) * filePageSize
    return results.slice(startIndex, startIndex + filePageSize)
  }, [filePage, filePageSize, results])

  const loadRules = async () => {
    setRulesLoading(true)
    try {
      const loadedRules = await fetchSearchRules()
      setRules(loadedRules)
    } catch (error) {
      console.error(error)
      message.error('加载搜索规则失败')
    } finally {
      setRulesLoading(false)
    }
  }

  useEffect(() => {
    void loadRules()
  }, [])

  useEffect(() => {
    const keyword = new URLSearchParams(location.search).get('keyword')
    if (keyword) {
      setPattern(keyword)
    }
  }, [location.search])

  useEffect(() => {
    if (!pagedResults.length) {
      if (selectedResultId) {
        setSelectedResultId('')
      }
      return
    }

    const currentPageContainsSelected = pagedResults.some(
      (item) => item.id === selectedResultId,
    )

    if (!currentPageContainsSelected) {
      setSelectedResultId(pagedResults[0].id)
    }
  }, [pagedResults, selectedResultId])

  const handleSearch = async () => {
    if (!pattern.trim()) {
      message.warning('请输入搜索模式')
      return
    }

    setSearching(true)
    setSearchCompleted(false)
    setResults([])
    setSelectedResultId('')
    setFilePage(1)

    try {
      const response = await searchJSContent({
        pattern: pattern.trim(),
        isRegex,
        caseSensitive,
      })
      const allResults = response?.data || []

      setResults(allResults)
      setSelectedResultId(allResults[0]?.id || '')
      setSearchCompleted(true)

      if (allResults.length > 0) {
        message.success(`找到 ${allResults.length} 个匹配文件`)
      }
    } catch (error) {
      console.error(error)
      const errorMessage =
        error instanceof Error &&
        (error.name === 'TimeoutError' ||
          error.message.toLowerCase().includes('timeout'))
          ? '搜索耗时过长，请缩小范围或稍后重试'
          : '搜索请求失败'
      message.error(errorMessage)
      setSearchCompleted(true)
    } finally {
      setSearching(false)
    }
  }

  const openSaveDialog = () => {
    saveForm.setFieldsValue({
      label: '',
      value: pattern,
    })
    setSaveOpen(true)
  }

  const handleCreateRule = async () => {
    try {
      const values = await saveForm.validateFields()
      await createSearchRule({
        label: values.label.trim(),
        value: values.value.trim(),
      })
      message.success('已保存自定义规则')
      setSaveOpen(false)
      await loadRules()
    } catch (error) {
      if (error instanceof Error) {
        console.error(error)
      }
    }
  }

  const handleDeleteRule = async (rule: SearchRule) => {
    if (!rule.id) {
      setRules((current) => current.filter((item) => item !== rule))
      return
    }

    try {
      await deleteSearchRule(rule.id)
      message.success('已删除搜索规则')
      await loadRules()
    } catch (error) {
      console.error(error)
      message.error('删除搜索规则失败')
    }
  }

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <Card title="数据检索">
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <div>
            <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
              对已采集的 JS 内容做二次搜索，支持正则、大小写控制和自定义规则复用。
            </Typography.Paragraph>
            <div
              style={{
                display: 'flex',
                gap: 12,
                alignItems: 'stretch',
                flexWrap: 'wrap',
              }}
            >
              <div style={{ flex: '1 1 420px', minWidth: 280 }}>
                <Input
                  value={pattern}
                  placeholder="输入正则表达式或关键词"
                  onChange={(event) => setPattern(event.target.value)}
                  onPressEnter={() => void handleSearch()}
                  prefix={<SearchOutlined />}
                  style={{ width: '100%' }}
                />
              </div>
              <Space wrap size={8}>
                <Button type="primary" loading={searching} onClick={() => void handleSearch()}>
                  搜索
                </Button>
                <Button onClick={openSaveDialog} disabled={!pattern.trim()} icon={<PlusOutlined />}>
                  保存为规则
                </Button>
              </Space>
            </div>
          </div>

          <Space size={24} wrap>
            <Checkbox checked={isRegex} onChange={(event) => setIsRegex(event.target.checked)}>
              正则表达式
            </Checkbox>
            <Checkbox
              checked={caseSensitive}
              onChange={(event) => setCaseSensitive(event.target.checked)}
            >
              区分大小写
            </Checkbox>
          </Space>

          <div>
            <Typography.Text strong>常用模式</Typography.Text>
            <div style={{ marginTop: 12 }}>
              <Spin spinning={rulesLoading}>
                <Space wrap>
                  {rules.length ? (
                    rules.map((rule) => (
                      <Tag
                        key={rule.id || `${rule.label}-${rule.value}`}
                        closable
                        icon={<SearchOutlined />}
                        style={{ paddingInline: 8, lineHeight: '28px', cursor: 'pointer' }}
                        onClick={() => setPattern(rule.value)}
                        onClose={(event) => {
                          event.preventDefault()
                          void handleDeleteRule(rule)
                        }}
                      >
                        {rule.label}
                      </Tag>
                    ))
                  ) : (
                    <Typography.Text type="secondary">暂无已保存规则</Typography.Text>
                  )}
                </Space>
              </Spin>
            </div>
          </div>

          {results.length > 0 ? (
            <Alert
              type="success"
              showIcon
              message={`找到 ${results.length} 个文件，共 ${totalMatches} 处匹配`}
            />
          ) : null}
        </Space>
      </Card>

      {searching ? (
        <Card>
          <div style={{ display: 'grid', placeItems: 'center', minHeight: 240 }}>
            <Spin size="large" tip="正在搜索 JS 内容..." />
          </div>
        </Card>
      ) : results.length > 0 ? (
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={9}>
            <Card title="匹配文件">
              <List
                dataSource={pagedResults}
                renderItem={(result) => (
                  <List.Item
                    style={{
                      cursor: 'pointer',
                      borderRadius: 8,
                      paddingInline: 12,
                      background:
                        selectedResult?.id === result.id ? 'rgba(22,119,255,0.08)' : 'transparent',
                    }}
                    onClick={() => setSelectedResultId(result.id)}
                  >
                    <List.Item.Meta
                      title={
                        <Typography.Text ellipsis style={{ maxWidth: '100%' }}>
                          {result.url}
                        </Typography.Text>
                      }
                      description={<Tag>{result.totalMatches} 处匹配</Tag>}
                    />
                  </List.Item>
                )}
              />
              {results.length > 0 ? (
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'flex-end',
                    marginTop: 16,
                    width: '100%',
                    overflowX: 'auto',
                    overflowY: 'hidden',
                    paddingBottom: 4,
                  }}
                >
                  <Pagination
                    style={{ minWidth: 'max-content' }}
                    current={filePage}
                    pageSize={filePageSize}
                    total={results.length}
                    responsive
                    showSizeChanger
                    pageSizeOptions={['10', '20', '50']}
                    onChange={(page, pageSize) => {
                      setFilePage(page)
                      setFilePageSize(pageSize)
                    }}
                  />
                </div>
              ) : null}
            </Card>
          </Col>

          <Col xs={24} xl={15}>
            <Card title="匹配详情">
              {selectedResult ? (
                <Space direction="vertical" size={16} style={{ width: '100%' }}>
                  <Alert
                    type="info"
                    showIcon
                    message={
                      <Space direction="vertical" size={4}>
                        <Typography.Link href={selectedResult.url} target="_blank">
                          {selectedResult.url}
                        </Typography.Link>
                        <Typography.Text type="secondary">
                          匹配次数：{selectedResult.totalMatches}
                        </Typography.Text>
                      </Space>
                    }
                  />

                  {selectedResult.totalMatches > 30 ? (
                    <Alert type="warning" showIcon message="由于性能考虑，仅展示前 30 条匹配" />
                  ) : null}

                  <List
                    dataSource={selectedResult.matches}
                    renderItem={(match, index) => (
                      <List.Item key={`${selectedResult.id}-${index}`}>
                        <Space direction="vertical" size={8} style={{ width: '100%' }}>
                          <Typography.Text type="secondary">第 {match.line} 行</Typography.Text>
                          {renderMatchContent(match)}
                        </Space>
                      </List.Item>
                    )}
                  />
                </Space>
              ) : (
                <Empty description="点击左侧结果查看详情" />
              )}
            </Card>
          </Col>
        </Row>
      ) : searchCompleted ? (
        <Card>
          <Empty description="未找到匹配内容">
            <Alert
              type="info"
              showIcon
              style={{ textAlign: 'left', maxWidth: 420, margin: '0 auto' }}
              message="搜索建议"
              description={
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  <li>检查正则表达式是否正确</li>
                  <li>尝试更简单的关键词</li>
                  <li>调整大小写敏感设置</li>
                  <li>确认目标数据已采集完成</li>
                </ul>
              }
            />
          </Empty>
        </Card>
      ) : (
        <Card>
          <Empty description="输入搜索模式开始检索" />
        </Card>
      )}

      <Modal
        title="保存为自定义规则"
        open={saveOpen}
        onCancel={() => setSaveOpen(false)}
        onOk={() => void handleCreateRule()}
        okText="保存"
        cancelText="取消"
      >
        <Form form={saveForm} layout="vertical">
          <Form.Item
            label="规则名称"
            name="label"
            rules={[{ required: true, message: '请输入规则名称' }]}
          >
            <Input placeholder="例如：常见 Token" />
          </Form.Item>
          <Form.Item
            label="规则内容"
            name="value"
            rules={[{ required: true, message: '请输入规则内容' }]}
          >
            <Input.TextArea rows={4} placeholder="默认带入当前搜索模式，可继续调整后保存" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
