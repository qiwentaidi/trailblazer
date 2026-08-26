import {
  getCodecDefaultMode,
  getCodecOperation,
  runCodecOperation,
} from './operations';

describe('codec operations', () => {
  test('encodes and decodes base64 text', () => {
    const operation = getCodecOperation('base64');

    const encoded = runCodecOperation(
      operation,
      getCodecDefaultMode(operation),
      'hello',
      {},
    );

    expect(encoded).toBe('aGVsbG8=');
    expect(runCodecOperation(operation, 'decode', encoded, {})).toBe('hello');
  });

  test('encrypts and decrypts AES ciphertext with hex payloads', () => {
    const operation = getCodecOperation('aes');
    const options = {
      key: '0123456789abcdef',
      keyFormat: 'UTF8',
      keySize: '128',
      iv: '0123456789abcdef',
      ivFormat: 'UTF8',
      mode: 'CBC',
      padding: 'Pkcs7',
      outputFormat: 'Hex',
      inputFormat: 'Hex',
    };

    const ciphertext = runCodecOperation(operation, 'encode', 'demo', options);

    expect(ciphertext).toMatch(/^[0-9a-f]+$/i);
    expect(runCodecOperation(operation, 'decode', ciphertext, options)).toBe(
      'demo',
    );
  });

  test('encrypts and decrypts SM4 ciphertext', () => {
    const operation = getCodecOperation('sm4');
    const options = {
      key: '0123456789abcdef',
      keyFormat: 'UTF8',
      iv: '0123456789abcdef',
      ivFormat: 'UTF8',
      mode: 'CBC',
      outputFormat: 'Hex',
      inputFormat: 'Hex',
    };

    const ciphertext = runCodecOperation(
      operation,
      'encode',
      '{"ok":true}',
      options,
    );

    expect(ciphertext).toMatch(/^[0-9a-f]+$/i);
    expect(runCodecOperation(operation, 'decode', ciphertext, options)).toBe(
      '{"ok":true}',
    );
  });
});
