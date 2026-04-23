import { ConfigProvider } from 'antd';
import 'antd/dist/reset.css';
import enUS from 'antd/locale/en_US';
import zhCN from 'antd/locale/zh_CN';
import React, { useEffect, useState } from 'react';

import config from '@/utils/config';

function LocaleWrapper({ children }: { children: React.ReactElement }) {
  // read initial locale synchronously so Antd has correct locale on first render
  const pick = (l: string | null) => {
    if (l === 'zh-CN') return zhCN;
    return enUS;
  };
  let initial: typeof zhCN | typeof enUS | undefined = undefined;
  const stored = window.localStorage.getItem('umi_locale') || null;
  initial = pick(stored);

  const [locale, setLocale] = useState<typeof zhCN | typeof enUS | undefined>(
    initial,
  );

  useEffect(() => {
    const read = () => {
      let l: string | null = null;
      try {
        l = window.localStorage.getItem('umi_locale') || null;
      } catch {
        l = null;
      }
      setLocale(pick(l));
    };

    const onStorage = (ev: StorageEvent) => {
      if (ev.key === 'umi_locale') read();
    };

    const onLocaleChange = (ev: Event) => {
      // CustomEvent detail carries the locale string when header controls switch language.
      const possible = ev as CustomEvent | Event;
      if (possible && typeof (possible as CustomEvent).detail !== 'undefined') {
        const d = (possible as CustomEvent).detail;
        if (d) setLocale(pick(String(d)));
      }
    };

    window.addEventListener('storage', onStorage);
    window.addEventListener('localechange', onLocaleChange as EventListener);

    const favicon =
      document.querySelector<HTMLLinkElement>('link[rel="icon"]') ||
      document.createElement('link');
    favicon.rel = 'icon';
    favicon.href = config.logoPath;
    if (!favicon.parentNode) {
      document.head.appendChild(favicon);
    }

    return () => {
      window.removeEventListener('storage', onStorage);
      window.removeEventListener(
        'localechange',
        onLocaleChange as EventListener,
      );
    };
  }, []);

  return <ConfigProvider locale={locale}>{children}</ConfigProvider>;
}

export function rootContainer(container: React.ReactElement) {
  return <LocaleWrapper>{container}</LocaleWrapper>;
}

// ensure mobile viewport meta exists (adds meta tag if not present)
try {
  if (typeof window !== 'undefined') {
    const hasVp = document.querySelector('meta[name="viewport"]');
    if (!hasVp) {
      const m = document.createElement('meta');
      m.name = 'viewport';
      m.content = 'width=device-width,initial-scale=1,maximum-scale=1';
      document.head.appendChild(m);
    }
  }
} catch {
  // ignore in non-DOM environments
}
