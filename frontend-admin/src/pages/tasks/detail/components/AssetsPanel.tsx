import { Card, Empty, Input, Select, Space, Table, Typography } from 'antd';
import { useEffect, useMemo, useState } from 'react';

import type { AssetData } from '@/types/task';
import { normalizeAssetBuckets } from './taskDetailUtils';

interface Props {
  assets: AssetData | null;
}

const ASSET_TYPE_LABELS = {
  email: '邮箱',
  phone: '手机号',
  idCard: '身份证',
  ipUrl: 'IP/URL',
  apiRoot: 'API Root',
  apiRouter: 'API Router',
} as const;

type AssetType = keyof typeof ASSET_TYPE_LABELS;

type AssetRow = {
  key: string;
  type: AssetType;
  typeLabel: string;
  value: string;
  source: string;
};

const DEFAULT_PAGE_SIZE = 10;

const toAssetRows = (
  assets: ReturnType<typeof normalizeAssetBuckets>,
): AssetRow[] =>
  (Object.keys(ASSET_TYPE_LABELS) as AssetType[]).flatMap((type) =>
    assets[type].map((item, index) => ({
      key: `${type}-${index}-${item.value}`,
      type,
      typeLabel: ASSET_TYPE_LABELS[type],
      value: item.value,
      source: item.sources.join('\n'),
    })),
  );

export default function AssetsPanel({ assets }: Props) {
  const [selectedType, setSelectedType] = useState<'all' | AssetType>('all');
  const [keyword, setKeyword] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const normalizedAssets = useMemo(
    () => normalizeAssetBuckets(assets),
    [assets],
  );
  const assetRows = useMemo(
    () => toAssetRows(normalizedAssets),
    [normalizedAssets],
  );
  const filteredRows = useMemo(
    () =>
      assetRows.filter((row) => {
        const matchesType = selectedType === 'all' || row.type === selectedType;
        const term = keyword.trim().toLowerCase();
        const matchesKeyword =
          !term ||
          row.typeLabel.toLowerCase().includes(term) ||
          row.value.toLowerCase().includes(term) ||
          row.source.toLowerCase().includes(term);
        return matchesType && matchesKeyword;
      }),
    [assetRows, keyword, selectedType],
  );

  const typeOptions = useMemo(
    () => [
      { label: '全部类型', value: 'all' },
      ...(Object.keys(ASSET_TYPE_LABELS) as AssetType[]).map((type) => ({
        label: `${ASSET_TYPE_LABELS[type]} (${normalizedAssets[type].length})`,
        value: type,
      })),
    ],
    [normalizedAssets],
  );

  useEffect(() => {
    setPage(1);
  }, [assets, keyword, selectedType]);

  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(filteredRows.length / pageSize));
    if (page > maxPage) {
      setPage(maxPage);
    }
  }, [filteredRows.length, page, pageSize]);

  if (!assets) {
    return <Empty description="暂无资产数据" />;
  }

  return (
    <Card
      size="small"
      title="资产详情"
      extra={
        <Space wrap>
          <Typography.Text type="secondary">
            当前 {filteredRows.length} 条
          </Typography.Text>
          <Input.Search
            allowClear
            value={keyword}
            placeholder="搜索类型、内容或来源"
            style={{ width: 240 }}
            onChange={(event) => setKeyword(event.target.value)}
          />
          <Select
            value={selectedType}
            options={typeOptions}
            style={{ minWidth: 180 }}
            onChange={(value) => setSelectedType(value)}
          />
        </Space>
      }
    >
      {assetRows.length ? (
        <Table<AssetRow>
          rowKey="key"
          size="small"
          dataSource={filteredRows}
          pagination={{
            current: page,
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: ['10', '20', '50'],
            showTotal: (total) => `共 ${total} 条`,
            onChange: (nextPage, nextPageSize) => {
              setPage(nextPage);
              if (nextPageSize !== pageSize) {
                setPageSize(nextPageSize);
              }
            },
          }}
          columns={[
            {
              title: '类型',
              dataIndex: 'typeLabel',
              width: 140,
            },
            {
              title: '内容',
              dataIndex: 'value',
              ellipsis: false,
              render: (value: string) => (
                <Typography.Text
                  style={{
                    display: 'block',
                    maxWidth: '100%',
                    minWidth: '0',
                    wordBreak: 'break-word',
                    overflowWrap: 'anywhere',
                    whiteSpace: 'normal',
                  }}
                >
                  {value}
                </Typography.Text>
              ),
            },
            {
              title: '来源',
              dataIndex: 'source',
              width: 280,
              ellipsis: false,
              render: (value: string) =>
                value ? (
                  <Typography.Text
                    style={{
                      display: 'block',
                      maxWidth: '100%',
                      minWidth: '0',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      overflowWrap: 'anywhere',
                    }}
                  >
                    {value}
                  </Typography.Text>
                ) : (
                  <Typography.Text type="secondary">-</Typography.Text>
                ),
            },
          ]}
        />
      ) : (
        <Empty description="暂无资产明细" />
      )}
    </Card>
  );
}
