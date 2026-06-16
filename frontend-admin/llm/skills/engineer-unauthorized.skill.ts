import {
  buildPMToEngineerHandoff,
  engineerSolutions,
  unauthorizedDetectionCapabilities,
} from './unauthorized-agent-context';

export const meta = {
  id: 'agent:engineer-unauthorized',
  name: 'Engineer For Unauthorized Detection',
  description: '接收产品经理提出的未授权检测问题，结合平台现状输出工程化解决方案。',
  inputs: {
    questions: '可选，产品经理问题列表；为空时默认处理内置问题集。',
  },
  outputs: '能力现状、问题对应方案、实现建议与预期收益',
};

export const actions = {
  async getCapabilityBaseline() {
    return unauthorizedDetectionCapabilities;
  },

  async proposeSolutions() {
    return {
      handoff: buildPMToEngineerHandoff(),
      solutions: engineerSolutions,
    };
  },
};

export default { meta, actions };
