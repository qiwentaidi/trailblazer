declare module 'jsencrypt' {
  export default class JSEncrypt {
    constructor(options?: { default_key_size?: string });
    getKey(): unknown;
    getPublicKey(): string;
    getPrivateKey(): string;
    setPublicKey(key: string): void;
    setPrivateKey(key: string): void;
    encrypt(input: string): string | false;
    decrypt(input: string): string | false;
  }
}

declare module 'sm-crypto' {
  export const sm2: {
    doEncrypt(input: string, publicKey: string, cipherMode?: number): string;
    doDecrypt(input: string, privateKey: string, cipherMode?: number): string;
    generateKeyPairHex(): { publicKey: string; privateKey: string };
  };

  export const sm4: {
    encrypt(
      input: string,
      key: string,
      options?: {
        mode?: 'cbc' | 'ecb';
        iv?: string;
        output?: 'array' | 'string';
      },
    ): number[] | string;
    decrypt(
      input: string,
      key: string,
      options?: {
        mode?: 'cbc' | 'ecb';
        iv?: string;
        output?: 'array' | 'string';
      },
    ): number[] | string;
  };

  const sm: {
    sm2: typeof sm2;
    sm4: typeof sm4;
  };

  export default sm;
}
