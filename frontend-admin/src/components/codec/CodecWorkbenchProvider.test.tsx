import { fireEvent, render, screen } from '@testing-library/react';

import CodecWorkbenchProvider from './CodecWorkbenchProvider';

describe('CodecWorkbenchProvider', () => {
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
      value: ResizeObserverMock,
    });

    Object.defineProperty(navigator, 'clipboard', {
      writable: true,
      value: {
        writeText: jest.fn().mockResolvedValue(undefined),
      },
    });
  });

  beforeEach(() => {
    localStorage.clear();
    jest.clearAllMocks();
  });

  test('opens the drawer from the floating button and computes output', async () => {
    render(
      <CodecWorkbenchProvider>
        <div>content</div>
      </CodecWorkbenchProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: /加解密工具|code/i }));

    expect(await screen.findByText('前端加解密工具')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Hex\b/i }));
    fireEvent.change(screen.getByPlaceholderText('输入待处理内容'), {
      target: { value: 'AB' },
    });

    expect(screen.getByDisplayValue('4142')).toBeInTheDocument();
  });
});
