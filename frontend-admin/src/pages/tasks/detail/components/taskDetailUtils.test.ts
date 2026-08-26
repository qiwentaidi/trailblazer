import {
  buildProtocolTraceFlow,
  buildProtocolTraceStackFingerprint,
  countTreeNodes,
  formatTreeNodePreview,
  groupProtocolTracesByAlgorithms,
  groupProtocolTracesByStackFingerprint,
  normalizeRiskLevel,
} from './taskDetailUtils';

describe('task detail helpers', () => {
  test('counts nested site-tree nodes recursively', () => {
    expect(
      countTreeNodes([
        {
          id: 'root',
          label: 'Root',
          children: [
            { id: 'child-1', label: 'Child 1' },
            {
              id: 'child-2',
              label: 'Child 2',
              children: [{ id: 'grandchild', label: 'Grandchild' }],
            },
          ],
        },
      ]),
    ).toBe(4);
  });

  test('normalizes legacy risk levels to info', () => {
    expect(normalizeRiskLevel('legacy')).toBe('info');
    expect(normalizeRiskLevel(undefined)).toBe('info');
  });

  test('formats tree node preview from backend payload fields', () => {
    expect(
      formatTreeNodePreview({
        id: 'node-1',
        label: 'Node 1',
        url: 'https://example.com/node-1',
        responseBody: { ok: true },
      }),
    ).toBe('{\n  "ok": true\n}');
  });

  test('prefers request body when response body is absent', () => {
    expect(
      formatTreeNodePreview({
        id: 'node-2',
        label: 'Node 2',
        requestBody: 'POST /api/demo',
      }),
    ).toBe('POST /api/demo');
  });

  test('groups protocol traces by normalized algorithm set', () => {
    const groups = groupProtocolTracesByAlgorithms([
      {
        trace_id: 'trace-1',
        algorithms: ['aes', 'rsa'],
      },
      {
        trace_id: 'trace-2',
        algorithms: ['rsa', 'aes'],
      },
      {
        trace_id: 'trace-3',
        algorithms: ['sm4'],
      },
      {
        trace_id: 'trace-4',
      },
    ]);

    expect(groups).toHaveLength(3);
    expect(groups[0]).toMatchObject({
      id: 'aes | rsa',
      label: 'aes + rsa',
    });
    expect(groups[0].traces.map((trace) => trace.trace_id)).toEqual([
      'trace-1',
      'trace-2',
    ]);
    expect(groups[2]).toMatchObject({
      id: 'unclassified',
      label: '未识别算法',
    });
  });

  test('builds request and response protocol lanes from trace evidence', () => {
    const flow = buildProtocolTraceFlow({
      trace_id: 'trace-1',
      request_before_transform: '{"query":"demo"}',
      final_request_body: 'cipher-request',
      session_materials: {
        latest_response_ciphertext: 'Y2lwaGVyLXJlc3BvbnNl',
        latest_response_plaintext: '{"code":200}',
      },
      request_steps: [
        {
          source: 'JSON.stringify',
          algorithm: 'json.stringify',
          input_preview: '{"query":"demo"}',
          output_preview: '{"query":"demo"}',
          captured_at_ms: 100,
        },
        {
          source: 'crypto.encrypt',
          algorithm: 'aes-cbc',
          input_preview: '{"query":"demo"}',
          output_preview: 'cipher-request',
          captured_at_ms: 200,
        },
      ],
      response_steps: [
        {
          source: 'window.atob',
          algorithm: 'base64.decode',
          input_preview: 'Y2lwaGVyLXJlc3BvbnNl',
          output_preview: 'cipher-response',
          captured_at_ms: 300,
        },
        {
          source: 'crypto.decrypt',
          algorithm: 'aes-cbc',
          input_preview: 'cipher-response',
          output_preview: '{"code":200}',
          captured_at_ms: 400,
        },
      ],
    });

    expect(flow.summary).toMatchObject({
      hasRequestLane: true,
      hasResponseLane: true,
      hasResponseCiphertext: true,
      hasResponsePlaintext: true,
      finalResponseSource: '捕获到的响应明文',
    });
    expect(flow.requestLane.map((step) => step.title)).toEqual([
      '原始请求明文',
      'JSON.stringify',
      'crypto.encrypt',
      '最终发包请求体',
    ]);
    expect(flow.responseLane.map((step) => step.title)).toEqual([
      '原始响应密文',
      'window.atob',
      'crypto.decrypt',
      '响应明文',
    ]);
    expect(flow.responseLane[2]).toMatchObject({
      kind: 'response',
      algorithm: 'aes-cbc',
      output: '{"code":200}',
    });
  });

  test('suppresses mirrored request plaintext when it only duplicates response plaintext', () => {
    const flow = buildProtocolTraceFlow({
      trace_id: 'trace-mirrored',
      request_before_transform: '{"code":200}',
      session_materials: {
        latest_response_ciphertext: 'cipher-response',
        latest_response_plaintext: '{"code":200}',
      },
      response_steps: [
        {
          source: 'crypto.decrypt',
          algorithm: 'aes-cbc',
          input_preview: 'cipher-response',
          output_preview: '{"code":200}',
          captured_at_ms: 100,
        },
      ],
    });

    expect(flow.requestLane.map((step) => step.title)).toEqual([]);
    expect(flow.responseLane.map((step) => step.title)).toEqual([
      '原始响应密文',
      'crypto.decrypt',
      '响应明文',
    ]);
  });

  test('does not treat opaque hex-like response material as decrypted plaintext', () => {
    const flow = buildProtocolTraceFlow({
      trace_id: 'trace-opaque-response',
      session_materials: {
        latest_response_plaintext:
          '"4869f146b63d96e8d1c886ae2105fb6dbbf56673503fc8c2d783bd4ef2005e76a572037243afcd80639bcabba46fd2155a555e80ef831a7f807536e6ddc23ac2052f592d0551ff6792b1d8ab8d945cb5"',
      },
      response_steps: [
        {
          source: 'window.atob',
          algorithm: 'base64.decode',
          input_preview: 'TVRSRFJUTFZORUU1TkVaR01EQkZSVExFTjBSQ05FVTVSRQ==',
          output_preview:
            '04CE9E4A94FF00EE9D7DB4E9DFA01FFA1E6E146630B760142CAE625B163AF9A85AE63480E9DE9E1A76D1BD88C8B21C75E7325932C66A5C028DB5CB3966C4B4B7D7',
          captured_at_ms: 100,
        },
      ],
    });

    expect(flow.summary).toMatchObject({
      hasResponseCiphertext: false,
      hasResponsePlaintext: false,
      finalResponseSource: '未捕获到响应明文',
    });
    expect(flow.responseLane.map((step) => step.title)).toEqual([]);
  });

  test('builds explicit request and response lanes without guessing', () => {
    const flow = buildProtocolTraceFlow({
      trace_id: 'trace-request-sm4',
      request_before_transform: '{}',
      final_request_body: '42ba39e60597915a113ce0ff23e61c18',
      request_headers: {
        gv59jppeesnw: 'AHc5bsRm',
        kqn29pkxstkn: '1776137632717',
        bpzhepzrvcjy: 'ec834bbbb8520d1f1473bf17023d0e13',
        '6zzbinypyphq': '689a4dc4',
      },
      session_materials: {
        sm4_key_hex: '34393932323837363337373534333339',
        nonce: 'AHc5bsRm',
        timestamp: '1776137632717',
        signature: 'ec834bbbb8520d1f1473bf17023d0e13',
        key_exchange_header: '689a4dc4',
        latest_response_ciphertext: 'TXpRek9UTTVNVGsxT1RJM05qY3pNek0=',
        latest_response_plaintext: '{}',
      },
      request_steps: [
        {
          source: 'JSON.stringify',
          algorithm: 'json.stringify',
          input_preview: '{}',
          output_preview: '{}',
          captured_at_ms: 100,
        },
        {
          source: 'window.atob',
          algorithm: 'base64.decode',
          input_preview: 'MzQzOTkzMjM4MzczNjMzMzczNTM0MzMzOQ==',
          output_preview: '34393932323837363337373534333339',
          captured_at_ms: 150,
        },
        {
          source: 'window.btoa',
          algorithm: 'base64.encode',
          input_preview: '42ba39e60597915a113ce0ff23e61c18',
          output_preview: 'NDJiYTM5ZTYwNTk3OTE1YTExM2NlMGZmMjNlNjFjMTg=',
          captured_at_ms: 200,
        },
      ],
      response_steps: [
        {
          source: 'window.atob',
          algorithm: 'base64.decode',
          input_preview: 'TXpRek9UTTVNVGsxT1RJM05qY3pNek0=',
          output_preview: '{}',
          captured_at_ms: 300,
        },
      ],
    });

    expect(flow.requestLane.map((step) => step.title)).toEqual([
      '原始请求明文',
      'window.atob',
      'SM4 密钥',
      'Nonce / IV',
      '请求头组装',
      '最终发包请求体',
    ]);
    expect(flow.responseLane.map((step) => step.title)).toEqual([
      '原始响应密文',
      'window.atob',
      '响应明文',
    ]);
    expect(flow.requestLane[1]).toMatchObject({
      algorithm: 'base64.decode',
      output: '34393932323837363337373534333339',
    });
    expect(flow.requestLane[2]).toMatchObject({
      input: undefined,
      output: '34393932323837363337373534333339',
      materialKeys: ['sm4_key_hex'],
    });
    expect(flow.requestLane[3]).toMatchObject({
      input: 'gv59jppeesnw',
      output: 'AHc5bsRm',
    });
    expect(flow.requestLane[4]).toMatchObject({
      output: expect.stringContaining('"gv59jppeesnw": "AHc5bsRm"'),
      materialKeys: expect.arrayContaining([
        'nonce',
        'timestamp',
        'signature',
        'key_exchange_header',
      ]),
    });
  });

  test('builds normalized stack fingerprints and groups traces by fingerprint', () => {
    const stack = `at decryptPayload (https://example.com/app.js:12:34)
at handleResponse (https://example.com/app.js:56:78)`;

    expect(buildProtocolTraceStackFingerprint(stack)).toBe(
      'decryptPayload (<url>) <- handleResponse (<url>)',
    );

    const groups = groupProtocolTracesByStackFingerprint([
      { trace_id: 'trace-1', stack },
      {
        trace_id: 'trace-2',
        stack: `at decryptPayload (https://example.com/app.js:88:99)
at handleResponse (https://example.com/app.js:66:77)`,
      },
      { trace_id: 'trace-3' },
    ]);

    expect(groups).toHaveLength(2);
    expect(groups[0].label).toBe(
      'decryptPayload (<url>) <- handleResponse (<url>)',
    );
    expect(groups[0].traces.map((trace) => trace.trace_id)).toEqual([
      'trace-1',
      'trace-2',
    ]);
    expect(groups[1].label).toBe('无调用栈');
  });
});
