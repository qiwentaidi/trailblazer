export type CodecMode = 'encode' | 'decode' | 'transform';

export type CodecOperationOption = {
  key: string;
  label: string;
  defaultValue: string;
  type?: 'input' | 'select';
  options?: string[];
  placeholder?: string;
};

export type CodecOperation = {
  id: string;
  name: string;
  category: 'encoding' | 'hash' | 'crypto' | 'format';
  description: string;
  encode?: (input: string, options?: Record<string, string>) => string;
  decode?: (input: string, options?: Record<string, string>) => string;
  transform?: (input: string, options?: Record<string, string>) => string;
  options?: CodecOperationOption[];
};

export type CodecWorkbenchState = {
  operationId: string;
  mode: CodecMode;
  input: string;
  options: Record<string, string>;
};

export type OpenCodecWorkbenchOptions = Partial<CodecWorkbenchState> & {
  replaceInput?: boolean;
};
