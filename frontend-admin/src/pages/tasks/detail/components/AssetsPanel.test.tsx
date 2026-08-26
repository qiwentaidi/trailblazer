import { fireEvent, render, screen } from '@testing-library/react';

import type { AssetData } from '@/types/task';
import AssetsPanel from './AssetsPanel';

const buildAssets = (): AssetData => ({
  taskId: 'task-1',
  taskName: '资产任务',
  email: [{ value: 'admin@example.com', source: ['站点树 · 首页接口'] }],
  idCard: [],
  phone: Array.from(
    { length: 11 },
    (_, index) => ({
      value: `138000000${String(index).padStart(2, '0')}`,
      source: [`风险 · 手机号泄露 ${index + 1}`],
    }),
  ),
  ipUrl: [
    {
      value:
        'https://example.com/this/is/a/very/very/very/very/very/very/very/very/long/url/that/should/wrap',
      source: ['站点树 · 首页接口', '风险 · URL 暴露'],
    },
  ],
  apiRoot: [],
  apiRouter: [],
  createdAt: '',
});

describe('AssetsPanel', () => {
  beforeAll(() => {
    class MessageChannelMock {
      port1 = {
        onmessage: null as ((event: { data?: unknown }) => void) | null,
      };

      port2 = {
        postMessage: (data?: unknown) => {
          if (this.port1.onmessage) {
            this.port1.onmessage({ data });
          }
        },
      };
    }

    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation((query) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    });

    Object.defineProperty(globalThis, 'MessageChannel', {
      writable: true,
      configurable: true,
      value: MessageChannelMock,
    });

    class ResizeObserverMock {
      observe = jest.fn();
      unobserve = jest.fn();
      disconnect = jest.fn();
    }

    Object.defineProperty(globalThis, 'ResizeObserver', {
      writable: true,
      configurable: true,
      value: ResizeObserverMock,
    });
  });

  test('renders assets in a searchable paginated table', () => {
    render(<AssetsPanel assets={buildAssets()} />);

    expect(screen.getByText('资产详情')).toBeInTheDocument();
    expect(screen.getByText('共 13 条')).toBeInTheDocument();
    expect(screen.getAllByText('来源').length).toBeGreaterThan(0);

    fireEvent.change(screen.getByPlaceholderText('搜索类型、内容或来源'), {
      target: { value: '手机号泄露' },
    });

    expect(screen.getByText('当前 11 条')).toBeInTheDocument();
    expect(screen.getByText('13800000000')).toBeInTheDocument();
    expect(screen.getByText('风险 · 手机号泄露 1')).toBeInTheDocument();
    expect(
      screen.queryByText(/https:\/\/example\.com/i),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByTitle('2'));

    expect(screen.getByText('13800000010')).toBeInTheDocument();
    expect(screen.queryByText('13800000000')).not.toBeInTheDocument();
  });

  test('renders long asset values with truncation-safe styles', () => {
    render(<AssetsPanel assets={buildAssets()} />);

    fireEvent.change(screen.getByPlaceholderText('搜索类型、内容或来源'), {
      target: { value: 'example.com' },
    });

    const urlValue = screen
      .getByText(/https:\/\/example\.com/i)
      .closest('span');

    expect(urlValue).toHaveStyle({
      display: 'block',
      maxWidth: '100%',
      minWidth: '0',
      whiteSpace: 'nowrap',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
    });
  });

  test('filters assets by keyword across value and source', () => {
    render(<AssetsPanel assets={buildAssets()} />);

    fireEvent.change(screen.getByPlaceholderText('搜索类型、内容或来源'), {
      target: { value: '首页接口' },
    });

    expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    expect(screen.getByText(/https:\/\/example\.com/i)).toBeInTheDocument();
    expect(screen.queryByText('13800000000')).not.toBeInTheDocument();
  });
});
