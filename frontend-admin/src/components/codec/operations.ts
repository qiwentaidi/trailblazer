import CryptoJS from 'crypto-js';
import JSEncrypt from 'jsencrypt';
import sm from 'sm-crypto';

import type { CodecMode, CodecOperation, CodecOperationOption } from './types';

const codecCategories = [
  { id: 'encoding', label: '编码 / 解码' },
  { id: 'hash', label: '摘要 / 哈希' },
  { id: 'crypto', label: '加密 / 解密' },
  { id: 'format', label: '格式处理' },
] as const;

const getAvailableModes = (operation: CodecOperation): CodecMode[] => {
  const modes: CodecMode[] = [];
  if (operation.encode) {
    modes.push('encode');
  }
  if (operation.decode) {
    modes.push('decode');
  }
  if (operation.transform) {
    modes.push('transform');
  }
  return modes;
};

const getDefaultOptions = (operation?: CodecOperation) =>
  (operation?.options || []).reduce<Record<string, string>>(
    (result, option) => {
      result[option.key] = option.defaultValue;
      return result;
    },
    {},
  );

const formatError = (prefix: string, error: unknown) =>
  `[${prefix}: ${error instanceof Error ? error.message : '未知错误'}]`;

const utf8ToBase64 = (input: string) =>
  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(input));

const base64ToHex = (input: string) =>
  CryptoJS.enc.Base64.parse(input.replace(/\s+/g, '')).toString(
    CryptoJS.enc.Hex,
  );

const base64ToUtf8 = (input: string) =>
  CryptoJS.enc.Base64.parse(input.replace(/\s+/g, '')).toString(
    CryptoJS.enc.Utf8,
  );

const bytesToHex = (bytes: Uint8Array | number[]) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const bytesToBase64 = (bytes: Uint8Array | number[]) =>
  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Hex.parse(bytesToHex(bytes)));

const utf8ToHex = (input: string, length: number) =>
  CryptoJS.enc.Utf8.parse(input.padEnd(length, '\0').slice(0, length)).toString(
    CryptoJS.enc.Hex,
  );

const parseKeyMaterial = (
  value: string,
  format: string,
  byteLength: number,
) => {
  switch (format.toLowerCase()) {
    case 'hex':
      return CryptoJS.enc.Hex.parse(value);
    case 'base64':
      return CryptoJS.enc.Base64.parse(value);
    default:
      return CryptoJS.enc.Utf8.parse(
        value.padEnd(byteLength, '0').slice(0, byteLength),
      );
  }
};

const cryptoModes = {
  CBC: CryptoJS.mode.CBC,
  ECB: CryptoJS.mode.ECB,
  CFB: CryptoJS.mode.CFB,
  OFB: CryptoJS.mode.OFB,
  CTR: CryptoJS.mode.CTR,
} as const;

const cryptoPaddings = {
  Pkcs7: CryptoJS.pad.Pkcs7,
  ZeroPadding: CryptoJS.pad.ZeroPadding,
  NoPadding: CryptoJS.pad.NoPadding,
  Iso10126: CryptoJS.pad.Iso10126,
  AnsiX923: CryptoJS.pad.AnsiX923,
} as const;

const getCryptoMode = (mode?: string) =>
  cryptoModes[(mode || 'CBC').toUpperCase() as keyof typeof cryptoModes] ||
  CryptoJS.mode.CBC;

const getCryptoPadding = (padding?: string) =>
  cryptoPaddings[(padding || 'Pkcs7') as keyof typeof cryptoPaddings] ||
  CryptoJS.pad.Pkcs7;

const buildCipherParams = (input: string, inputFormat: string) => {
  if ((inputFormat || 'Base64').toLowerCase() === 'hex') {
    return CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(input.trim()),
    });
  }
  return input.trim();
};

const encodeBase64 = (input: string) => {
  try {
    return utf8ToBase64(input);
  } catch (error) {
    return formatError('Base64 编码错误', error);
  }
};

const decodeBase64 = (input: string) => {
  try {
    return base64ToUtf8(input);
  } catch (error) {
    return formatError('Base64 解码错误', error);
  }
};

const encodeUrl = (input: string) => {
  try {
    return encodeURIComponent(input);
  } catch (error) {
    return formatError('URL 编码错误', error);
  }
};

const decodeUrl = (input: string) => {
  try {
    return decodeURIComponent(input);
  } catch (error) {
    return formatError('URL 解码错误', error);
  }
};

const encodeHex = (input: string) => {
  try {
    return CryptoJS.enc.Utf8.parse(input).toString(CryptoJS.enc.Hex);
  } catch (error) {
    return formatError('Hex 编码错误', error);
  }
};

const decodeHex = (input: string) => {
  try {
    return CryptoJS.enc.Hex.parse(input.replace(/\s+/g, '')).toString(
      CryptoJS.enc.Utf8,
    );
  } catch (error) {
    return formatError('Hex 解码错误', error);
  }
};

const encodeUnicode = (input: string) =>
  Array.from(input)
    .map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`)
    .join('');

const decodeUnicode = (input: string) => {
  try {
    return input.replace(/\\u([0-9a-fA-F]{4})/g, (_, code) =>
      String.fromCharCode(parseInt(code, 16)),
    );
  } catch (error) {
    return formatError('Unicode 解码错误', error);
  }
};

const decodeJwt = (input: string) => {
  try {
    const parts = input.trim().split('.');
    if (parts.length < 2) {
      throw new Error('JWT 格式无效');
    }
    const normalizeBase64 = (value: string) => {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
      const remainder = normalized.length % 4;
      return remainder
        ? `${normalized}${'='.repeat(4 - remainder)}`
        : normalized;
    };
    return JSON.stringify(
      {
        header: JSON.parse(base64ToUtf8(normalizeBase64(parts[0]))),
        payload: JSON.parse(base64ToUtf8(normalizeBase64(parts[1]))),
      },
      null,
      2,
    );
  } catch (error) {
    return formatError('JWT 解码错误', error);
  }
};

const md5Hash = (input: string) =>
  CryptoJS.MD5(input).toString(CryptoJS.enc.Hex);
const sha1Hash = (input: string) =>
  CryptoJS.SHA1(input).toString(CryptoJS.enc.Hex);
const sha256Hash = (input: string) =>
  CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);
const sha512Hash = (input: string) =>
  CryptoJS.SHA512(input).toString(CryptoJS.enc.Hex);

const transformSm3 = (input: string) => {
  try {
    return (sm as unknown as { sm3: (value: string) => string }).sm3(input);
  } catch (error) {
    return formatError('SM3 计算错误', error);
  }
};

const aesEncrypt = (input: string, options?: Record<string, string>) => {
  try {
    const keySize = parseInt(options?.keySize || '128', 10);
    const key = parseKeyMaterial(
      options?.key || '0123456789abcdef',
      options?.keyFormat || 'UTF8',
      keySize / 8,
    );
    const iv = parseKeyMaterial(
      options?.iv || '0123456789abcdef',
      options?.ivFormat || 'UTF8',
      16,
    );
    const encrypted = CryptoJS.AES.encrypt(input, key, {
      iv,
      mode: getCryptoMode(options?.mode),
      padding: getCryptoPadding(options?.padding),
    });
    return (options?.outputFormat || 'Base64').toLowerCase() === 'hex'
      ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
      : encrypted.toString();
  } catch (error) {
    return formatError('AES 加密错误', error);
  }
};

const aesDecrypt = (input: string, options?: Record<string, string>) => {
  try {
    const keySize = parseInt(options?.keySize || '128', 10);
    const key = parseKeyMaterial(
      options?.key || '0123456789abcdef',
      options?.keyFormat || 'UTF8',
      keySize / 8,
    );
    const iv = parseKeyMaterial(
      options?.iv || '0123456789abcdef',
      options?.ivFormat || 'UTF8',
      16,
    );
    const decrypted = CryptoJS.AES.decrypt(
      buildCipherParams(input, options?.inputFormat || 'Base64'),
      key,
      {
        iv,
        mode: getCryptoMode(options?.mode),
        padding: getCryptoPadding(options?.padding),
      },
    );
    return (
      decrypted.toString(CryptoJS.enc.Utf8) ||
      '[解密结果为空，请检查密钥 / IV / 模式是否匹配]'
    );
  } catch (error) {
    return formatError('AES 解密错误', error);
  }
};

const desEncrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key = parseKeyMaterial(
      options?.key || '12345678',
      options?.keyFormat || 'UTF8',
      8,
    );
    const iv = parseKeyMaterial(
      options?.iv || '12345678',
      options?.ivFormat || 'UTF8',
      8,
    );
    const encrypted = CryptoJS.DES.encrypt(input, key, {
      iv,
      mode: getCryptoMode(options?.mode),
      padding: getCryptoPadding(options?.padding),
    });
    return (options?.outputFormat || 'Base64').toLowerCase() === 'hex'
      ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
      : encrypted.toString();
  } catch (error) {
    return formatError('DES 加密错误', error);
  }
};

const desDecrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key = parseKeyMaterial(
      options?.key || '12345678',
      options?.keyFormat || 'UTF8',
      8,
    );
    const iv = parseKeyMaterial(
      options?.iv || '12345678',
      options?.ivFormat || 'UTF8',
      8,
    );
    const decrypted = CryptoJS.DES.decrypt(
      buildCipherParams(input, options?.inputFormat || 'Base64'),
      key,
      {
        iv,
        mode: getCryptoMode(options?.mode),
        padding: getCryptoPadding(options?.padding),
      },
    );
    return decrypted.toString(CryptoJS.enc.Utf8) || '[解密结果为空]';
  } catch (error) {
    return formatError('DES 解密错误', error);
  }
};

const tripleDesEncrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key = parseKeyMaterial(
      options?.key || '123456789012345678901234',
      options?.keyFormat || 'UTF8',
      24,
    );
    const iv = parseKeyMaterial(
      options?.iv || '12345678',
      options?.ivFormat || 'UTF8',
      8,
    );
    const encrypted = CryptoJS.TripleDES.encrypt(input, key, {
      iv,
      mode: getCryptoMode(options?.mode),
      padding: getCryptoPadding(options?.padding),
    });
    return (options?.outputFormat || 'Base64').toLowerCase() === 'hex'
      ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
      : encrypted.toString();
  } catch (error) {
    return formatError('3DES 加密错误', error);
  }
};

const tripleDesDecrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key = parseKeyMaterial(
      options?.key || '123456789012345678901234',
      options?.keyFormat || 'UTF8',
      24,
    );
    const iv = parseKeyMaterial(
      options?.iv || '12345678',
      options?.ivFormat || 'UTF8',
      8,
    );
    const decrypted = CryptoJS.TripleDES.decrypt(
      buildCipherParams(input, options?.inputFormat || 'Base64'),
      key,
      {
        iv,
        mode: getCryptoMode(options?.mode),
        padding: getCryptoPadding(options?.padding),
      },
    );
    return decrypted.toString(CryptoJS.enc.Utf8) || '[解密结果为空]';
  } catch (error) {
    return formatError('3DES 解密错误', error);
  }
};

const rc4Encrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key =
      (options?.keyFormat || 'UTF8').toLowerCase() === 'hex'
        ? CryptoJS.enc.Hex.parse(options?.key || '')
        : CryptoJS.enc.Utf8.parse(options?.key || 'secretkey');
    const encrypted = CryptoJS.RC4.encrypt(input, key);
    return (options?.outputFormat || 'Base64').toLowerCase() === 'hex'
      ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
      : encrypted.toString();
  } catch (error) {
    return formatError('RC4 加密错误', error);
  }
};

const rc4Decrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key =
      (options?.keyFormat || 'UTF8').toLowerCase() === 'hex'
        ? CryptoJS.enc.Hex.parse(options?.key || '')
        : CryptoJS.enc.Utf8.parse(options?.key || 'secretkey');
    const decrypted = CryptoJS.RC4.decrypt(
      buildCipherParams(input, options?.inputFormat || 'Base64'),
      key,
    );
    return decrypted.toString(CryptoJS.enc.Utf8) || '[解密结果为空]';
  } catch (error) {
    return formatError('RC4 解密错误', error);
  }
};

const rabbitEncrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key = CryptoJS.enc.Utf8.parse(options?.key || 'secretkey');
    const iv = options?.iv ? CryptoJS.enc.Utf8.parse(options.iv) : undefined;
    const encrypted = CryptoJS.Rabbit.encrypt(input, key, iv ? { iv } : {});
    return (options?.outputFormat || 'Base64').toLowerCase() === 'hex'
      ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
      : encrypted.toString();
  } catch (error) {
    return formatError('Rabbit 加密错误', error);
  }
};

const rabbitDecrypt = (input: string, options?: Record<string, string>) => {
  try {
    const key = CryptoJS.enc.Utf8.parse(options?.key || 'secretkey');
    const iv = options?.iv ? CryptoJS.enc.Utf8.parse(options.iv) : undefined;
    const decrypted = CryptoJS.Rabbit.decrypt(
      buildCipherParams(input, options?.inputFormat || 'Base64'),
      key,
      iv ? { iv } : {},
    );
    return decrypted.toString(CryptoJS.enc.Utf8) || '[解密结果为空]';
  } catch (error) {
    return formatError('Rabbit 解密错误', error);
  }
};

const sm4Encrypt = (input: string, options?: Record<string, string>) => {
  try {
    const keyHex =
      (options?.keyFormat || 'UTF8').toLowerCase() === 'hex'
        ? (options?.key || '').padEnd(32, '0').slice(0, 32)
        : utf8ToHex(options?.key || '0123456789abcdef', 16);
    const ivHex =
      (options?.ivFormat || 'UTF8').toLowerCase() === 'hex'
        ? (options?.iv || '').padEnd(32, '0').slice(0, 32)
        : utf8ToHex(options?.iv || '0123456789abcdef', 16);
    const encrypted = sm.sm4.encrypt(input, keyHex, {
      mode: (options?.mode || 'CBC').toUpperCase() === 'ECB' ? 'ecb' : 'cbc',
      iv: ivHex,
      output: 'array',
    }) as number[];
    return (options?.outputFormat || 'Hex').toLowerCase() === 'base64'
      ? bytesToBase64(encrypted)
      : bytesToHex(encrypted);
  } catch (error) {
    return formatError('SM4 加密错误', error);
  }
};

const sm4Decrypt = (input: string, options?: Record<string, string>) => {
  try {
    const keyHex =
      (options?.keyFormat || 'UTF8').toLowerCase() === 'hex'
        ? (options?.key || '').padEnd(32, '0').slice(0, 32)
        : utf8ToHex(options?.key || '0123456789abcdef', 16);
    const ivHex =
      (options?.ivFormat || 'UTF8').toLowerCase() === 'hex'
        ? (options?.iv || '').padEnd(32, '0').slice(0, 32)
        : utf8ToHex(options?.iv || '0123456789abcdef', 16);
    const ciphertext =
      (options?.inputFormat || 'Hex').toLowerCase() === 'base64'
        ? base64ToHex(input)
        : input.trim();
    return (
      (sm.sm4.decrypt(ciphertext, keyHex, {
        mode: (options?.mode || 'CBC').toUpperCase() === 'ECB' ? 'ecb' : 'cbc',
        iv: ivHex,
        output: 'string',
      }) as string) || '[解密结果为空]'
    );
  } catch (error) {
    return formatError('SM4 解密错误', error);
  }
};

const sm2Encrypt = (input: string, options?: Record<string, string>) => {
  try {
    if (!options?.publicKey) {
      throw new Error('请提供 SM2 公钥');
    }
    return sm.sm2.doEncrypt(input, options.publicKey, 1);
  } catch (error) {
    return formatError('SM2 加密错误', error);
  }
};

const sm2Decrypt = (input: string, options?: Record<string, string>) => {
  try {
    if (!options?.privateKey) {
      throw new Error('请提供 SM2 私钥');
    }
    return (
      sm.sm2.doDecrypt(input.trim(), options.privateKey, 1) || '[解密结果为空]'
    );
  } catch (error) {
    return formatError('SM2 解密错误', error);
  }
};

const rsaEncrypt = (input: string, options?: Record<string, string>) => {
  try {
    if (!options?.publicKey) {
      throw new Error('请提供 RSA 公钥');
    }
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(options.publicKey);
    const result = encryptor.encrypt(input);
    if (!result) {
      throw new Error('公钥格式无效或输入过长');
    }
    return result;
  } catch (error) {
    return formatError('RSA 加密错误', error);
  }
};

const rsaDecrypt = (input: string, options?: Record<string, string>) => {
  try {
    if (!options?.privateKey) {
      throw new Error('请提供 RSA 私钥');
    }
    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(options.privateKey);
    const result = decryptor.decrypt(input.trim());
    if (!result) {
      throw new Error('私钥格式无效或密文不匹配');
    }
    return result;
  } catch (error) {
    return formatError('RSA 解密错误', error);
  }
};

const formatJson = (input: string) => {
  try {
    return JSON.stringify(JSON.parse(input), null, 2);
  } catch (error) {
    return formatError('JSON 格式化错误', error);
  }
};

const minifyJson = (input: string) => {
  try {
    return JSON.stringify(JSON.parse(input));
  } catch (error) {
    return formatError('JSON 压缩错误', error);
  }
};

const symmetricOptions = (
  keyLabel: string,
  keyDefault: string,
  ivLabel: string,
  ivDefault: string,
  modeOptions: string[],
  paddingOptions?: string[],
  keyFormatOptions: string[] = ['UTF8', 'Hex'],
  ivFormatOptions: string[] = ['UTF8', 'Hex'],
): CodecOperationOption[] => [
  { key: 'key', label: keyLabel, defaultValue: keyDefault },
  {
    key: 'keyFormat',
    label: 'Key 格式',
    defaultValue: keyFormatOptions[0],
    type: 'select',
    options: keyFormatOptions,
  },
  { key: 'iv', label: ivLabel, defaultValue: ivDefault },
  {
    key: 'ivFormat',
    label: 'IV 格式',
    defaultValue: ivFormatOptions[0],
    type: 'select',
    options: ivFormatOptions,
  },
  {
    key: 'mode',
    label: '模式',
    defaultValue: modeOptions[0],
    type: 'select',
    options: modeOptions,
  },
  ...(paddingOptions
    ? [
        {
          key: 'padding',
          label: '填充',
          defaultValue: paddingOptions[0],
          type: 'select' as const,
          options: paddingOptions,
        },
      ]
    : []),
  {
    key: 'outputFormat',
    label: '输出格式',
    defaultValue: 'Base64',
    type: 'select',
    options: ['Base64', 'Hex'],
  },
  {
    key: 'inputFormat',
    label: '输入格式',
    defaultValue: 'Base64',
    type: 'select',
    options: ['Base64', 'Hex'],
  },
];

export const codecOperations: CodecOperation[] = [
  {
    id: 'base64',
    name: 'Base64',
    category: 'encoding',
    description: '常用 Base64 编码与解码。',
    encode: encodeBase64,
    decode: decodeBase64,
  },
  {
    id: 'url',
    name: 'URL',
    category: 'encoding',
    description: 'URL 百分号编码与解码。',
    encode: encodeUrl,
    decode: decodeUrl,
  },
  {
    id: 'hex',
    name: 'Hex',
    category: 'encoding',
    description: 'UTF-8 文本与十六进制互转。',
    encode: encodeHex,
    decode: decodeHex,
  },
  {
    id: 'unicode',
    name: 'Unicode',
    category: 'encoding',
    description: '字符串与 \\uXXXX 转义互转。',
    encode: encodeUnicode,
    decode: decodeUnicode,
  },
  {
    id: 'jwt',
    name: 'JWT 解码',
    category: 'encoding',
    description: '解析 JWT header / payload。',
    decode: decodeJwt,
  },
  {
    id: 'md5',
    name: 'MD5',
    category: 'hash',
    description: '计算 MD5 摘要。',
    transform: md5Hash,
  },
  {
    id: 'sha1',
    name: 'SHA-1',
    category: 'hash',
    description: '计算 SHA-1 摘要。',
    transform: sha1Hash,
  },
  {
    id: 'sha256',
    name: 'SHA-256',
    category: 'hash',
    description: '计算 SHA-256 摘要。',
    transform: sha256Hash,
  },
  {
    id: 'sha512',
    name: 'SHA-512',
    category: 'hash',
    description: '计算 SHA-512 摘要。',
    transform: sha512Hash,
  },
  {
    id: 'sm3',
    name: 'SM3',
    category: 'hash',
    description: '计算 SM3 国密摘要。',
    transform: transformSm3,
  },
  {
    id: 'aes',
    name: 'AES',
    category: 'crypto',
    description: '常见前端 AES 加解密，支持多模式与多种输入输出格式。',
    encode: aesEncrypt,
    decode: aesDecrypt,
    options: [
      { key: 'key', label: '密钥', defaultValue: '0123456789abcdef' },
      {
        key: 'keyFormat',
        label: 'Key 格式',
        defaultValue: 'UTF8',
        type: 'select',
        options: ['UTF8', 'Hex', 'Base64'],
      },
      {
        key: 'keySize',
        label: '密钥位数',
        defaultValue: '128',
        type: 'select',
        options: ['128', '192', '256'],
      },
      { key: 'iv', label: 'IV', defaultValue: '0123456789abcdef' },
      {
        key: 'ivFormat',
        label: 'IV 格式',
        defaultValue: 'UTF8',
        type: 'select',
        options: ['UTF8', 'Hex', 'Base64'],
      },
      {
        key: 'mode',
        label: '模式',
        defaultValue: 'CBC',
        type: 'select',
        options: ['CBC', 'ECB', 'CFB', 'OFB', 'CTR'],
      },
      {
        key: 'padding',
        label: '填充',
        defaultValue: 'Pkcs7',
        type: 'select',
        options: ['Pkcs7', 'ZeroPadding', 'NoPadding', 'Iso10126', 'AnsiX923'],
      },
      {
        key: 'outputFormat',
        label: '输出格式',
        defaultValue: 'Base64',
        type: 'select',
        options: ['Base64', 'Hex'],
      },
      {
        key: 'inputFormat',
        label: '输入格式',
        defaultValue: 'Base64',
        type: 'select',
        options: ['Base64', 'Hex'],
      },
    ],
  },
  {
    id: 'des',
    name: 'DES',
    category: 'crypto',
    description: 'DES 对称加解密。',
    encode: desEncrypt,
    decode: desDecrypt,
    options: symmetricOptions(
      '密钥',
      '12345678',
      'IV',
      '12345678',
      ['CBC', 'ECB', 'CFB', 'OFB'],
      ['Pkcs7', 'ZeroPadding', 'NoPadding'],
    ),
  },
  {
    id: '3des',
    name: '3DES',
    category: 'crypto',
    description: '3DES 对称加解密。',
    encode: tripleDesEncrypt,
    decode: tripleDesDecrypt,
    options: symmetricOptions(
      '密钥',
      '123456789012345678901234',
      'IV',
      '12345678',
      ['CBC', 'ECB', 'CFB', 'OFB'],
      ['Pkcs7', 'ZeroPadding', 'NoPadding'],
    ),
  },
  {
    id: 'rc4',
    name: 'RC4',
    category: 'crypto',
    description: 'RC4 流加密。',
    encode: rc4Encrypt,
    decode: rc4Decrypt,
    options: [
      { key: 'key', label: '密钥', defaultValue: 'secretkey' },
      {
        key: 'keyFormat',
        label: 'Key 格式',
        defaultValue: 'UTF8',
        type: 'select',
        options: ['UTF8', 'Hex'],
      },
      {
        key: 'outputFormat',
        label: '输出格式',
        defaultValue: 'Base64',
        type: 'select',
        options: ['Base64', 'Hex'],
      },
      {
        key: 'inputFormat',
        label: '输入格式',
        defaultValue: 'Base64',
        type: 'select',
        options: ['Base64', 'Hex'],
      },
    ],
  },
  {
    id: 'rabbit',
    name: 'Rabbit',
    category: 'crypto',
    description: 'Rabbit 流加密。',
    encode: rabbitEncrypt,
    decode: rabbitDecrypt,
    options: [
      { key: 'key', label: '密钥', defaultValue: 'secretkey' },
      { key: 'iv', label: 'IV', defaultValue: '' },
      {
        key: 'outputFormat',
        label: '输出格式',
        defaultValue: 'Base64',
        type: 'select',
        options: ['Base64', 'Hex'],
      },
      {
        key: 'inputFormat',
        label: '输入格式',
        defaultValue: 'Base64',
        type: 'select',
        options: ['Base64', 'Hex'],
      },
    ],
  },
  {
    id: 'sm4',
    name: 'SM4',
    category: 'crypto',
    description: 'SM4 国密对称加解密，适合前端协议调试。',
    encode: sm4Encrypt,
    decode: sm4Decrypt,
    options: [
      { key: 'key', label: '密钥', defaultValue: '0123456789abcdef' },
      {
        key: 'keyFormat',
        label: 'Key 格式',
        defaultValue: 'UTF8',
        type: 'select',
        options: ['UTF8', 'Hex'],
      },
      { key: 'iv', label: 'IV', defaultValue: '0123456789abcdef' },
      {
        key: 'ivFormat',
        label: 'IV 格式',
        defaultValue: 'UTF8',
        type: 'select',
        options: ['UTF8', 'Hex'],
      },
      {
        key: 'mode',
        label: '模式',
        defaultValue: 'CBC',
        type: 'select',
        options: ['CBC', 'ECB'],
      },
      {
        key: 'outputFormat',
        label: '输出格式',
        defaultValue: 'Hex',
        type: 'select',
        options: ['Hex', 'Base64'],
      },
      {
        key: 'inputFormat',
        label: '输入格式',
        defaultValue: 'Hex',
        type: 'select',
        options: ['Hex', 'Base64'],
      },
    ],
  },
  {
    id: 'sm2',
    name: 'SM2',
    category: 'crypto',
    description: 'SM2 国密非对称加解密。',
    encode: sm2Encrypt,
    decode: sm2Decrypt,
    options: [
      {
        key: 'publicKey',
        label: '公钥',
        defaultValue: '',
        placeholder: '加密时填写 Hex 公钥',
      },
      {
        key: 'privateKey',
        label: '私钥',
        defaultValue: '',
        placeholder: '解密时填写 Hex 私钥',
      },
    ],
  },
  {
    id: 'rsa',
    name: 'RSA',
    category: 'crypto',
    description: 'RSA 公钥加密 / 私钥解密。',
    encode: rsaEncrypt,
    decode: rsaDecrypt,
    options: [
      {
        key: 'publicKey',
        label: '公钥',
        defaultValue: '',
        placeholder: '加密时填写 PEM 公钥',
      },
      {
        key: 'privateKey',
        label: '私钥',
        defaultValue: '',
        placeholder: '解密时填写 PEM 私钥',
      },
    ],
  },
  {
    id: 'json-format',
    name: 'JSON 格式化',
    category: 'format',
    description: '格式化 JSON 文本。',
    transform: formatJson,
  },
  {
    id: 'json-minify',
    name: 'JSON 压缩',
    category: 'format',
    description: '压缩 JSON 文本。',
    transform: minifyJson,
  },
];

export const codecCategoryOptions = codecCategories;

export const codecOperationsByCategory = codecCategoryOptions.map(
  (category) => ({
    ...category,
    operations: codecOperations.filter(
      (operation) => operation.category === category.id,
    ),
  }),
);

export const getCodecOperation = (operationId?: string) =>
  codecOperations.find((operation) => operation.id === operationId) ||
  codecOperations[0];

export const getCodecDefaultMode = (operation?: CodecOperation): CodecMode =>
  getAvailableModes(operation || codecOperations[0])[0] || 'transform';

export const getCodecAvailableModes = (operation?: CodecOperation) =>
  getAvailableModes(operation || codecOperations[0]);

export const getCodecDefaultOptions = getDefaultOptions;

export const runCodecOperation = (
  operation: CodecOperation | undefined,
  mode: CodecMode,
  input: string,
  options: Record<string, string>,
) => {
  if (!operation) {
    return '';
  }

  try {
    switch (mode) {
      case 'encode':
        return operation.encode?.(input, options) || '[当前操作不支持编码]';
      case 'decode':
        return operation.decode?.(input, options) || '[当前操作不支持解码]';
      default:
        return operation.transform?.(input, options) || '[当前操作不支持转换]';
    }
  } catch (error) {
    return formatError(`${operation.name} 执行错误`, error);
  }
};
