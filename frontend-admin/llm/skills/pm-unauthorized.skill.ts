import {
  buildPMToEngineerHandoff,
  pmQuestions,
  unauthorizedDetectionCapabilities,
} from './unauthorized-agent-context';

export const meta = {
  id: 'agent:pm-unauthorized',
  name: 'Product Manager For Unauthorized Detection',
  description: '围绕平台当前未授权检测能力提出产品问题，并整理交付给工程侧的需求上下文。',
  inputs: {
    focus: '可选，指定关注方向，如误报、分级、证据、工作流。',
  },
  outputs: '当前能力摘要、问题清单、面向工程师的交接上下文',
};

export const actions = {
  async getCapabilitySummary() {
    return unauthorizedDetectionCapabilities;
  },

  async listKeyQuestions() {
    return pmQuestions;
  },

  async createEngineerHandoff() {
    return buildPMToEngineerHandoff();
  },
};

export default { meta, actions };
