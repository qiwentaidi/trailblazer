export interface CapabilityPoint {
  title: string;
  detail: string;
  evidence: string[];
}

export interface PMQuestion {
  id: string;
  category: string;
  question: string;
  intent: string;
}

export interface EngineerSolution {
  questionId: string;
  problem: string;
  proposal: string;
  implementation: string[];
  expectedOutcome: string;
}

export const unauthorizedDetectionCapabilities: CapabilityPoint[] = [
  {
    title: '未授权结果已支持噪声标注',
    detail:
      '平台会对“未授权访问”漏洞做聚类和拒绝模板识别，避免把统一认证拦截页大量误报为真实漏洞。',
    evidence: [
      '../trailblazer/pkg/core/scanexec/target.go',
      'pkg/web/unauth_noise.go',
      'frontend-admin/src/types/task.ts',
    ],
  },
  {
    title: '已支持认证失败关键词配置',
    detail:
      '扫描选项中存在 authentication 关键词列表，可用于辅助判定响应更像鉴权失败还是正常业务数据。',
    evidence: [
      '../trailblazer/pkg/lib/sdk.go',
      '../trailblazer/pkg/config/options.go',
      'config.yaml',
    ],
  },
  {
    title: '结果层已保留未授权判定证据',
    detail:
      '风险对象中包含 confidenceReason、denyTemplateKind、denyTemplateLabel、denyTemplateCount、dataExposure、staticContexts 等字段。',
    evidence: [
      'frontend-admin/src/types/task.ts',
      'frontend-admin/src/services/tasks.ts',
    ],
  },
  {
    title: '平台已具备协议还原与静态上下文辅助',
    detail:
      '任务结果支持 protocol trace、响应解密、静态上下文等，可用于提高未授权结果的解释性和复核效率。',
    evidence: [
      'frontend-admin/src/services/tasks.ts',
      'frontend-admin/src/types/task.ts',
    ],
  },
  {
    title: '平台已有 learned_auth_patterns 基础设施',
    detail:
      '后端数据库已存在 learned_auth_patterns 表，说明系统具备沉淀认证拒绝模式的方向基础。',
    evidence: ['../trailblazer/pkg/core/database/sqlite.go'],
  },
];

export const pmQuestions: PMQuestion[] = [
  {
    id: 'pm-unauth-coverage',
    category: '检测覆盖',
    question:
      '当前未授权检测是否只覆盖“匿名访问成功”，还是也覆盖“低权限越权访问高权限接口”？',
    intent: '确认能力边界，避免产品对“未授权”与“越权”混用导致预期失真。',
  },
  {
    id: 'pm-unauth-baseline',
    category: '判定逻辑',
    question:
      '平台现在如何证明一个接口是真的未授权，而不是统一认证拒绝模板、默认公开接口或静态资源？',
    intent: '明确核心判定依据和证据链，减少误报争议。',
  },
  {
    id: 'pm-unauth-false-positive',
    category: '误报控制',
    question:
      '对于大量返回相同 200 页面、登录失效 JSON、网关兜底页的目标，误报率怎么量化、怎么压降？',
    intent: '把“可用性”问题转成可跟踪指标和规则优化项。',
  },
  {
    id: 'pm-unauth-severity',
    category: '风险分级',
    question:
      '未授权结果现在的高、中、低风险分级依据是什么，是否和数据暴露敏感度、接口业务动作绑定？',
    intent: '确保风险排序符合客户处置优先级。',
  },
  {
    id: 'pm-unauth-evidence',
    category: '结果解释',
    question:
      '分析人员看到一条未授权结果时，能否直接知道返回了什么敏感数据、为什么判成高置信、是否命中过认证拒绝模板？',
    intent: '缩短人工复核路径，提升结果可解释性。',
  },
  {
    id: 'pm-unauth-auth-learning',
    category: '自学习',
    question:
      '不同客户的认证失败文案差异很大，平台是否能自动学习某个站点的鉴权失败模板并复用到后续扫描？',
    intent: '推动从静态规则走向站点级自适应。',
  },
  {
    id: 'pm-unauth-diff',
    category: '对比验证',
    question:
      '平台是否支持“带登录态”和“不带登录态”的响应差异对比，来证明匿名访问拿到了本不该拿到的数据？',
    intent: '补强证据，降低“公开接口误判”为漏洞的风险。',
  },
  {
    id: 'pm-unauth-workflow',
    category: '处置流程',
    question:
      '扫描完成后，分析人员针对未授权结果的确认、忽略、聚类去重、批量处置流程是否足够顺手？',
    intent: '把检测能力延伸到结果消费效率。',
  },
];

export const engineerSolutions: EngineerSolution[] = [
  {
    questionId: 'pm-unauth-coverage',
    problem: '当前实现更偏向匿名未授权识别，低权限越权的检测边界没有被显式建模。',
    proposal: '把“匿名未授权”和“越权访问”拆成两个检测策略，并在结果类型上分层呈现。',
    implementation: [
      '在扫描配置中引入多身份上下文，支持 anonymous、low_privilege、admin 等身份档位。',
      '扩展漏洞类型和证据模型，区分 anonymous_access 与 privilege_escalation。',
      '前端结果页按检测策略展示，避免同一种标题承载不同问题。',
    ],
    expectedOutcome: '产品边界更清晰，后续可以分别优化两类问题的命中率与误报率。',
  },
  {
    questionId: 'pm-unauth-baseline',
    problem: '当前有认证拒绝模板识别，但对“为什么算成功访问”的正向证据表达还不够强。',
    proposal: '增加基线对比判定链路，用匿名响应、认证失败模板、业务成功特征三类信号联合判定。',
    implementation: [
      '为同一路由建立匿名请求和认证失败样本的差异比对。',
      '把状态码、响应长度、字段命中、结构相似度纳入统一评分模型。',
      '在结果中追加 baseline_reason 字段，展示命中规则。',
    ],
    expectedOutcome: '未授权结果从“像漏洞”提升为“有对比证据支撑的漏洞”。',
  },
  {
    questionId: 'pm-unauth-false-positive',
    problem: '统一网关页、SSO 失效页、前端路由兜底页会制造大批同质误报。',
    proposal: '把现有 deny template 聚类扩展为站点级模板库，并结合 AI/规则双判。',
    implementation: [
      '复用 learned_auth_patterns 持久化站点级认证拒绝模板。',
      '对 body 摘要、标题、重定向链、关键字段做指纹化聚类。',
      '对高频模板聚类做批量降权或默认折叠展示。',
    ],
    expectedOutcome: '批量噪声下降，人工主要处理真正有业务数据暴露的结果。',
  },
  {
    questionId: 'pm-unauth-severity',
    problem: '现有风险等级与数据敏感度、业务动作危险度的绑定还不够显式。',
    proposal: '建立未授权专属分级模型，把“读敏感数据”和“可执行业务动作”区分开。',
    implementation: [
      '复用 dataExposure 字段，补充 actionRisk 字段识别增删改、审批、导出等行为。',
      '定义高风险判定规则，例如敏感数据暴露、资金/权限修改、批量导出。',
      '在前端列表提供按暴露类型和动作类型筛选。',
    ],
    expectedOutcome: '排序更贴近真实处置优先级，减少高风险结果被噪声淹没。',
  },
  {
    questionId: 'pm-unauth-evidence',
    problem: '已有证据字段分散，分析人员仍需自己拼接判断逻辑。',
    proposal: '增加未授权证据摘要层，直接输出“为何判定、暴露了什么、建议怎么复核”。',
    implementation: [
      '在后端生成 vulnerability_evidence_summary。',
      '汇总 confidenceReason、dataExposure、staticContexts、protocol trace 关键信息。',
      '前端在风险详情中首屏展示证据摘要和复核建议。',
    ],
    expectedOutcome: '单条结果的理解成本下降，复核动作更标准化。',
  },
  {
    questionId: 'pm-unauth-auth-learning',
    problem: '认证失败关键词配置偏静态，面对客户私有网关和本地化文案适应性不足。',
    proposal: '把认证拒绝模板学习做成扫描后的站点画像能力。',
    implementation: [
      '从高频相似失败响应中提取模板并入库。',
      '允许人工确认模板后回写，形成半自动学习闭环。',
      '后续任务优先命中站点已学习模板，减少重复误报。',
    ],
    expectedOutcome: '系统逐步适应不同客户环境，越扫越准。',
  },
  {
    questionId: 'pm-unauth-diff',
    problem: '缺少登录态与匿名态的直接差异证据，容易和公开接口混淆。',
    proposal: '增加双态比对扫描模式，把差异内容作为漏洞证据的一部分。',
    implementation: [
      '利用现有 token 注入能力，支持同接口双请求采集。',
      '比对字段集合、记录条数、敏感字段出现情况和状态码差异。',
      '将差异摘要落到结果对象并在详情页高亮。',
    ],
    expectedOutcome: '公开接口和真实未授权接口更容易区分。',
  },
  {
    questionId: 'pm-unauth-workflow',
    problem: '即使检测准确，若结果无法高效聚类、过滤和批量处理，价值仍然打折。',
    proposal: '围绕未授权结果增加聚类视图和批量操作能力。',
    implementation: [
      '按 denyTemplateId、dataExposure、业务路径聚类展示。',
      '支持批量标记忽略、已确认、加入模板库。',
      '增加误报反馈入口，反哺规则和模板学习。',
    ],
    expectedOutcome: '分析员能先处理高价值簇，再回收整批噪声。',
  },
];

export function buildPMToEngineerHandoff() {
  return {
    capabilitySummary: unauthorizedDetectionCapabilities,
    questions: pmQuestions,
    expectedEngineerOutput: [
      '先判断问题是否已有部分能力支撑',
      '再指出当前实现缺口',
      '最后给出可落地的后端、前端、数据模型改造方案',
    ],
  };
}
