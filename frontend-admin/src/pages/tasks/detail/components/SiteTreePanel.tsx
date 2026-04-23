import { useEffect, useMemo, useState } from 'react';

import type { TreeProps } from 'antd';
import {
  Card,
  Descriptions,
  Empty,
  List,
  Spin,
  Tag,
  Tree,
  Typography,
} from 'antd';

import type { APIResource, JSResource, TreeNode } from '@/types/task';
interface Props {
  taskId: string;
  version?: number;
  treeData: TreeNode[];
  jsResources: JSResource[];
  apiResources: APIResource[];
  loading?: boolean;
}

const CODE_BLOCK_MAX_RENDER_CHARS = 20000;

const buildSearchNeedles = (value?: string) => {
  if (!value) {
    return [] as string[];
  }

  const normalized = value.trim();
  if (!normalized) {
    return [] as string[];
  }

  const needles = new Set<string>([normalized]);
  try {
    const parsed = new URL(normalized);
    needles.add(parsed.pathname + parsed.search);
    needles.add(parsed.pathname);
  } catch {
    // ignore parsing errors and keep the raw value only
  }

  return Array.from(needles)
    .map((item) => item.trim())
    .filter(Boolean)
    .sort((left, right) => right.length - left.length);
};

const includesNeedle = (text: string, needles: string[]) => {
  const normalized = text.toLowerCase();
  return needles.some((needle) => normalized.includes(needle.toLowerCase()));
};

const buildSnippet = (content: string, needles: string[]) => {
  const matchedNeedle = needles.find((needle) =>
    content.toLowerCase().includes(needle.toLowerCase()),
  );

  if (!matchedNeedle) {
    return content.slice(0, 240);
  }

  const lowerContent = content.toLowerCase();
  const lowerNeedle = matchedNeedle.toLowerCase();
  const start = lowerContent.indexOf(lowerNeedle);
  if (start < 0) {
    return content.slice(0, 240);
  }

  const snippetStart = Math.max(0, start - 120);
  const snippetEnd = Math.min(
    content.length,
    start + matchedNeedle.length + 120,
  );
  const prefix = snippetStart > 0 ? '...' : '';
  const suffix = snippetEnd < content.length ? '...' : '';
  return `${prefix}${content.slice(snippetStart, snippetEnd)}${suffix}`;
};

const formatNodeValue = (value: unknown) => {
  if (typeof value === 'string') {
    return value;
  }

  if (value == null) {
    return '';
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
};

const hasDisplayableValue = (value: unknown) => {
  if (value == null) {
    return false;
  }

  if (typeof value === 'string') {
    return Boolean(value.trim());
  }

  if (Array.isArray(value)) {
    return value.length > 0;
  }

  if (typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>).length > 0;
  }

  return true;
};

const dedupeBy = <T,>(items: T[], buildKey: (item: T) => string) => {
  const seen = new Set<string>();
  const result: T[] = [];

  for (const item of items) {
    const key = buildKey(item);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(item);
  }

  return result;
};

const renderCodeBlock = (
  title: string,
  value: unknown,
  emptyText = '暂无数据',
  maxHeight?: number,
) => {
  const formatted = formatNodeValue(value);
  const isTruncated = formatted.length > CODE_BLOCK_MAX_RENDER_CHARS;
  const displayValue = isTruncated
    ? `${formatted.slice(0, CODE_BLOCK_MAX_RENDER_CHARS)}\n\n... [内容过长，已截断显示前 ${CODE_BLOCK_MAX_RENDER_CHARS} 个字符]`
    : formatted;

  return (
    <Card size="small" title={title} styles={{ body: { paddingTop: 12 } }}>
      {formatted ? (
        <div style={{ display: 'grid', gap: 8 }}>
          {isTruncated ? (
            <Typography.Text type="secondary">
              内容过长，已截断显示前 {CODE_BLOCK_MAX_RENDER_CHARS} 个字符。
            </Typography.Text>
          ) : null}
          <pre
            style={{
              margin: 0,
              padding: 16,
              overflow: 'auto',
              maxHeight,
              borderRadius: 8,
              background: '#f6f8fa',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}
          >
            {displayValue}
          </pre>
        </div>
      ) : (
        <Typography.Text type="secondary">{emptyText}</Typography.Text>
      )}
    </Card>
  );
};

const findNode = (nodes: TreeNode[], key: string): TreeNode | null => {
  for (const node of nodes) {
    if (node.id === key) {
      return node;
    }

    if (node.children?.length) {
      const match = findNode(node.children, key);
      if (match) {
        return match;
      }
    }
  }

  return null;
};

const mapLeafSelectableTree = (
  nodes: TreeNode[],
): (TreeNode & { selectable?: boolean; children?: any[] })[] =>
  nodes.map((node) => {
    const children = node.children?.length
      ? mapLeafSelectableTree(node.children)
      : undefined;
    const isLeaf = !children?.length;

    return {
      ...node,
      selectable: isLeaf,
      children,
    };
  });

const normalizeComparableURL = (value?: string) => {
  if (!value) {
    return '';
  }

  const normalized = value.trim();
  if (!normalized) {
    return '';
  }

  try {
    const parsed = new URL(normalized);
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return normalized;
  }
};

const isJSNode = (node: TreeNode | null) => {
  if (!node) {
    return false;
  }

  if (node.nodeType === 'js-resource') {
    return true;
  }

  const candidates = [node.url, node.label, node.id]
    .filter(
      (item): item is string =>
        typeof item === 'string' && Boolean(item.trim()),
    )
    .map((item) => item.toLowerCase());

  return candidates.some((item) => item.includes('.js'));
};

export default function SiteTreePanel({
  treeData,
  jsResources,
  apiResources,
  loading,
}: Props) {
  const [selectedKey, setSelectedKey] = useState<string>('');

  useEffect(() => {
    setSelectedKey('');
  }, [treeData]);

  const selectedNode = useMemo(
    () => (selectedKey ? findNode(treeData, selectedKey) : null),
    [selectedKey, treeData],
  );
  const selectedNodeIsJS = useMemo(
    () => isJSNode(selectedNode),
    [selectedNode],
  );
  const selectedJSResource = useMemo(() => {
    if (!selectedNodeIsJS || !selectedNode) {
      return null;
    }

    const normalizedNodeURL = normalizeComparableURL(selectedNode.url);
    const normalizedLabel = selectedNode.label.trim().toLowerCase();

    return (
      jsResources.find((resource) => {
        const normalizedResourceURL = normalizeComparableURL(resource.url);
        if (normalizedNodeURL && normalizedResourceURL === normalizedNodeURL) {
          return true;
        }

        if (!normalizedLabel) {
          return false;
        }

        return resource.url.trim().toLowerCase().endsWith(normalizedLabel);
      }) || null
    );
  }, [jsResources, selectedNode, selectedNodeIsJS]);
  const searchNeedles = useMemo(
    () => buildSearchNeedles(selectedNode?.url),
    [selectedNode?.url],
  );
  const relatedJSResources = useMemo(
    () =>
      searchNeedles.length
        ? dedupeBy(
            jsResources.filter(
              (resource) =>
                includesNeedle(resource.url, searchNeedles) ||
                includesNeedle(resource.content, searchNeedles),
            ),
            (resource) => resource.url,
          )
        : [],
    [jsResources, searchNeedles],
  );
  const relatedAPIResources = useMemo(
    () =>
      searchNeedles.length
        ? dedupeBy(
            apiResources.filter((resource) => {
              const hasDynamicPayload =
                hasDisplayableValue(resource.requestBody) ||
                hasDisplayableValue(resource.responseBody);

              if (!hasDynamicPayload) {
                return false;
              }

              return (
                includesNeedle(resource.url, searchNeedles) ||
                includesNeedle(resource.requestBody || '', searchNeedles) ||
                includesNeedle(resource.responseBody || '', searchNeedles)
              );
            }),
            (resource) =>
              [
                resource.method || 'GET',
                resource.url,
                resource.requestBody || '',
                resource.responseBody || '',
                String(resource.responseCode ?? ''),
              ].join('\x00'),
          )
        : [],
    [apiResources, searchNeedles],
  );
  const rawContent = useMemo(() => {
    if (!selectedNode) {
      return '';
    }

    if (selectedNodeIsJS) {
      return selectedJSResource?.content || selectedNode.code || '';
    }

    return selectedNode.code;
  }, [selectedJSResource, selectedNode, selectedNodeIsJS]);
  const selectableTreeData = useMemo(
    () => mapLeafSelectableTree(treeData),
    [treeData],
  );
  const selectedNodeRequestBody = selectedNode?.requestBody;
  const selectedNodeResponseBody = selectedNode?.responseBody ?? selectedNode?.response;
  const hasSelectedNodeRequestBody =
    !selectedNodeIsJS && hasDisplayableValue(selectedNodeRequestBody);
  const hasSelectedNodeResponseBody =
    !selectedNodeIsJS && hasDisplayableValue(selectedNodeResponseBody);
  const hasSelectedNodeRawContent = hasDisplayableValue(rawContent);
  const hasDynamicSections =
    hasSelectedNodeRequestBody ||
    hasSelectedNodeResponseBody ||
    hasSelectedNodeRawContent ||
    relatedJSResources.length > 0 ||
    relatedAPIResources.length > 0;

  const treeProps: TreeProps['fieldNames'] = {
    title: 'label',
    key: 'id',
    children: 'children',
  };

  return (
    <div
      style={{
        display: 'grid',
        gap: 16,
        gridTemplateColumns: 'minmax(280px, 360px) minmax(0, 1fr)',
        alignItems: 'start',
      }}
    >
      <Card styles={{ body: { maxHeight: 760, overflow: 'auto' } }}>
        {treeData.length ? (
          <Tree
            treeData={selectableTreeData as any}
            fieldNames={treeProps}
            defaultExpandAll
            selectedKeys={selectedKey ? [selectedKey] : []}
            onSelect={(keys) => {
              const key = String(keys[0] || '');
              setSelectedKey(key);
            }}
          />
        ) : (
          <Empty description="暂无网站树数据" />
        )}
      </Card>

      <Card title="节点详情" styles={{ body: { paddingTop: 16 } }}>
        {selectedNode ? (
          <Spin spinning={Boolean(loading)}>
            <div style={{ display: 'grid', gap: 16 }}>
              <div style={{ display: 'grid', gap: 8 }}>
                <Typography.Title level={5} style={{ margin: 0 }}>
                  {selectedNode.label}
                </Typography.Title>
                <Typography.Text type="secondary">
                  节点 ID: {selectedNode.id}
                </Typography.Text>
              </div>

              <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label="URL">
                  {selectedNode.url || '-'}
                </Descriptions.Item>
                <Descriptions.Item label="状态码">
                  {selectedNode.statusCode ?? '-'}
                </Descriptions.Item>
              </Descriptions>

              {hasSelectedNodeRequestBody
                ? renderCodeBlock('请求体', selectedNodeRequestBody, '暂无请求体')
                : null}
              {hasSelectedNodeResponseBody
                ? renderCodeBlock('响应体', selectedNodeResponseBody, '暂无响应体')
                : null}
              {hasSelectedNodeRawContent
                ? renderCodeBlock('原始内容', rawContent, '暂无原始内容', 360)
                : null}

              {!selectedNodeIsJS && relatedJSResources.length > 0 ? (
                <Card
                  size="small"
                  title="相关 JS 内容"
                  extra={
                    <Typography.Text type="secondary">
                      {relatedJSResources.length} 条命中
                    </Typography.Text>
                  }
                >
                  <List
                    dataSource={relatedJSResources}
                    renderItem={(resource) => (
                      <List.Item>
                        <div
                          style={{ display: 'grid', gap: 8, width: '100%' }}
                        >
                          <Typography.Text strong>
                            {resource.url}
                          </Typography.Text>
                          <pre
                            style={{
                              margin: 0,
                              padding: 16,
                              overflow: 'auto',
                              borderRadius: 8,
                              background: '#f6f8fa',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                            }}
                          >
                            {buildSnippet(resource.content, searchNeedles)}
                          </pre>
                        </div>
                      </List.Item>
                    )}
                  />
                </Card>
              ) : null}

              {!selectedNodeIsJS && relatedAPIResources.length > 0 ? (
                <Card
                  size="small"
                  title="相关接口内容"
                  extra={
                    <Typography.Text type="secondary">
                      {relatedAPIResources.length} 条命中
                    </Typography.Text>
                  }
                >
                  <List
                    dataSource={relatedAPIResources}
                    renderItem={(resource) => (
                      <List.Item>
                        <div
                          style={{ display: 'grid', gap: 12, width: '100%' }}
                        >
                          <div
                            style={{
                              display: 'flex',
                              gap: 8,
                              flexWrap: 'wrap',
                            }}
                          >
                            <Tag color="blue">{resource.method || 'GET'}</Tag>
                            <Typography.Text strong>
                              {resource.url}
                            </Typography.Text>
                            {typeof resource.responseCode === 'number' ? (
                              <Tag>{resource.responseCode}</Tag>
                            ) : null}
                          </div>
                          {hasDisplayableValue(resource.requestBody)
                            ? renderCodeBlock(
                                '接口请求体',
                                resource.requestBody,
                                '暂无请求体',
                              )
                            : null}
                          {hasDisplayableValue(resource.responseBody)
                            ? renderCodeBlock(
                                '接口响应体',
                                resource.responseBody,
                                '暂无响应体',
                              )
                            : null}
                        </div>
                      </List.Item>
                    )}
                  />
                </Card>
              ) : null}

              {!hasDynamicSections ? (
                <Empty description="当前节点未命中可展示的动态请求或响应内容" />
              ) : null}
            </div>
          </Spin>
        ) : (
          <Empty description="点击左侧节点查看详情" />
        )}
      </Card>
    </div>
  );
}
