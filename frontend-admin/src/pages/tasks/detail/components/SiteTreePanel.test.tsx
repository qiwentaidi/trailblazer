import { fireEvent, render, screen } from '@testing-library/react';

import type { APIResource, JSResource, TreeNode } from '@/types/task';
import SiteTreePanel from './SiteTreePanel';

const buildTree = (): TreeNode[] => [
  {
    id: 'node-1',
    label: '首页接口',
    url: 'https://example.com/api/demo',
    statusCode: 200,
    requestBody: { page: 1 },
    responseBody: { ok: true, items: [1, 2] },
    code: '<html>raw payload</html>',
  },
];

const buildJSResources = (): JSResource[] => [
  {
    taskId: 'task-1',
    version: 1,
    url: 'https://example.com/static/app.js',
    content: 'const api = "/api/demo"; fetch("https://example.com/api/demo")',
  },
];

const buildAPIResources = (): APIResource[] => [
  {
    taskId: 'task-1',
    version: 1,
    url: 'https://example.com/api/demo',
    method: 'POST',
    requestBody: '{"page":1}',
    responseBody: '{"ok":true}',
    responseCode: 200,
  },
];

describe('SiteTreePanel', () => {
  beforeAll(() => {
    class ResizeObserverMock {
      observe() {}

      unobserve() {}

      disconnect() {}
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

    Object.defineProperty(window, 'ResizeObserver', {
      writable: true,
      configurable: true,
      value: ResizeObserverMock,
    });

    Object.defineProperty(globalThis, 'ResizeObserver', {
      writable: true,
      configurable: true,
      value: ResizeObserverMock,
    });
  });

  test('renders split detail sections including request, response and raw content', () => {
    render(
      <SiteTreePanel
        taskId="task-1"
        treeData={buildTree()}
        jsResources={buildJSResources()}
        apiResources={buildAPIResources()}
      />,
    );

    fireEvent.click(screen.getByText('首页接口'));

    expect(screen.getByText('节点详情')).toBeInTheDocument();
    expect(screen.getByText('请求体')).toBeInTheDocument();
    expect(screen.getByText('响应体')).toBeInTheDocument();
    expect(screen.getByText('原始内容')).toBeInTheDocument();
    expect(screen.getByText(/"page": 1/)).toBeInTheDocument();
    expect(screen.getByText(/"ok": true/)).toBeInTheDocument();
    expect(screen.getByText('<html>raw payload</html>')).toBeInTheDocument();
    expect(screen.getByText('相关 JS 内容')).toBeInTheDocument();
    expect(
      screen.getByText('https://example.com/static/app.js'),
    ).toBeInTheDocument();
    expect(screen.getByText('相关接口内容')).toBeInTheDocument();
    expect(
      screen.getAllByText('https://example.com/api/demo').length,
    ).toBeGreaterThan(0);
  });

  test('hides empty detail sections for static non-js nodes', () => {
    render(
      <SiteTreePanel
        taskId="task-1"
        treeData={[
          {
            id: 'css-node-1',
            label: 'app.css',
            url: 'https://example.com/static/app.css',
          },
        ]}
        jsResources={[]}
        apiResources={[]}
      />,
    );

    fireEvent.click(screen.getByText('app.css'));

    expect(screen.queryByText('请求体')).not.toBeInTheDocument();
    expect(screen.queryByText('响应体')).not.toBeInTheDocument();
    expect(screen.queryByText('原始内容')).not.toBeInTheDocument();
    expect(screen.queryByText('相关 JS 内容')).not.toBeInTheDocument();
    expect(screen.queryByText('相关接口内容')).not.toBeInTheDocument();
    expect(
      screen.getByText('当前节点未命中可展示的动态请求或响应内容'),
    ).toBeInTheDocument();
  });

  test('renders only raw content for js nodes', () => {
    render(
      <SiteTreePanel
        taskId="task-1"
        treeData={[
          {
            id: 'js-node-1',
            label: 'app.js',
            url: 'https://example.com/static/app.js',
            nodeType: 'js-resource',
            statusCode: 200,
          },
        ]}
        jsResources={buildJSResources()}
        apiResources={buildAPIResources()}
      />,
    );

    fireEvent.click(screen.getByText('app.js'));

    expect(screen.queryByText('请求体')).not.toBeInTheDocument();
    expect(screen.queryByText('响应体')).not.toBeInTheDocument();
    expect(screen.queryByText('相关 JS 内容')).not.toBeInTheDocument();
    expect(screen.queryByText('相关接口内容')).not.toBeInTheDocument();
    expect(screen.getByText('原始内容')).toBeInTheDocument();
    const rawContent = screen.getByText(
      'const api = "/api/demo"; fetch("https://example.com/api/demo")',
    );

    expect(rawContent).toBeInTheDocument();
    expect(rawContent.closest('pre')).toHaveStyle({
      maxHeight: '360px',
      overflow: 'auto',
    });
  });

  test('only allows selecting leaf nodes in the tree', () => {
    render(
      <SiteTreePanel
        taskId="task-1"
        treeData={[
          {
            id: 'parent-node',
            label: '父节点',
            children: [
              {
                id: 'leaf-node',
                label: '叶子节点',
                url: 'https://example.com/api/leaf',
                statusCode: 200,
                responseBody: { ok: true },
                code: 'leaf raw payload',
              },
            ],
          },
        ]}
        jsResources={[]}
        apiResources={[]}
      />,
    );

    fireEvent.click(screen.getByText('父节点'));
    expect(screen.getByText('点击左侧节点查看详情')).toBeInTheDocument();
    expect(screen.queryByText('leaf raw payload')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('叶子节点'));
    expect(screen.getByText('leaf raw payload')).toBeInTheDocument();
  });

  test('truncates oversized raw js content to avoid rendering stalls', () => {
    const hugeContent = `const largePayload = "${'A'.repeat(22000)}";`;

    render(
      <SiteTreePanel
        taskId="task-1"
        treeData={[
          {
            id: 'js-node-large',
            label: 'large.js',
            url: 'https://example.com/static/large.js',
            nodeType: 'js-resource',
            statusCode: 200,
          },
        ]}
        jsResources={[
          {
            taskId: 'task-1',
            version: 1,
            url: 'https://example.com/static/large.js',
            content: hugeContent,
          },
        ]}
        apiResources={[]}
      />,
    );

    fireEvent.click(screen.getByText('large.js'));

    expect(
      screen.getByText('内容过长，已截断显示前 20000 个字符。'),
    ).toBeInTheDocument();
    expect(screen.getByText(/\.\.\. \[内容过长，已截断显示前 20000 个字符\]/)).toBeInTheDocument();
    expect(screen.queryByText(hugeContent)).not.toBeInTheDocument();
  });

  test('deduplicates related api records and keeps all unique dynamic payloads', () => {
    render(
      <SiteTreePanel
        taskId="task-1"
        treeData={[
          {
            id: 'api-path-node',
            label: 'demo',
            url: 'https://example.com/api/demo',
          },
        ]}
        jsResources={[]}
        apiResources={[
          {
            taskId: 'task-1',
            version: 1,
            url: 'https://example.com/api/demo',
            method: 'POST',
            requestBody: '{"page":1}',
            responseBody: '{"ok":true}',
            responseCode: 200,
          },
          {
            taskId: 'task-1',
            version: 1,
            url: 'https://example.com/api/demo',
            method: 'POST',
            requestBody: '{"page":1}',
            responseBody: '{"ok":true}',
            responseCode: 200,
          },
          {
            taskId: 'task-1',
            version: 1,
            url: 'https://example.com/api/demo',
            method: 'POST',
            requestBody: '',
            responseBody: '',
            responseCode: 200,
          },
          {
            taskId: 'task-1',
            version: 1,
            url: 'https://example.com/api/demo',
            method: 'POST',
            requestBody: '{"page":2}',
            responseBody: '{"ok":false}',
            responseCode: 200,
          },
        ]}
      />,
    );

    fireEvent.click(screen.getByText('demo'));

    expect(screen.getByText('相关接口内容')).toBeInTheDocument();
    expect(screen.getByText('2 条命中')).toBeInTheDocument();
    expect(screen.getByText('{"page":1}')).toBeInTheDocument();
    expect(screen.getByText('{"page":2}')).toBeInTheDocument();
    expect(screen.getByText('{"ok":true}')).toBeInTheDocument();
    expect(screen.getByText('{"ok":false}')).toBeInTheDocument();
  });
});
