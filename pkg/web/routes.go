package web

import (
	"github.com/qiwentaidi/trailblazer/pkg/auth"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api")
	api.GET("/generate/uuid", generateUUID)
	{
		// 认证相关路由（无需认证）
		authGroup := api.Group("/auth")
		{
			authGroup.GET("/status", auth.GetAuthStatusHandler)
			authGroup.POST("/initialize", auth.InitializeAccountHandler)
			authGroup.POST("/login", auth.LoginHandler)
			authGroup.POST("/logout", auth.LogoutHandler)
		}

		// 需要认证的路由
		protected := api.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			protected.POST("/auth/change-password", auth.ChangePasswordHandler)
			// 用户信息
			protected.GET("/user/info", auth.GetUserInfoHandler)

			// 原有功能路由
			protected.POST("/generate/sitemap", generateSiteMap)
			protected.POST("/scan/start", startScan)
			protected.POST("/scan/stop", stopScan)
			// 人机协同测试：真实采集结果、人工决策和审计记录。
			protected.POST("/collaborative-tests", createCollaborativeTest)
			protected.GET("/collaborative-tests/:sessionId", getCollaborativeTest)
			protected.GET("/collaborative-tests/:sessionId/events", streamCollaborativeTest)
			protected.POST("/collaborative-tests/:sessionId/test-results/:resultId/runtime-decrypt", runtimeDecryptCollaborativeTestResult)
			protected.POST("/collaborative-tests/:sessionId/actions/:actionId", decideCollaborativeAction)
			protected.POST("/collaborative-tests/:sessionId/actions/:actionId/execute", executeCollaborativeAction)
			protected.GET("/config", getConfig)
			protected.POST("/config", saveConfig)

			// 任务详情查询
			protected.GET("/task/:taskId", getTaskDetail)
			protected.GET("/task/:taskId/versions", getTaskVersions)
			protected.GET("/task/:taskId/tree", getTaskTree)
			protected.GET("/task/:taskId/site-map", getTaskSiteMap)
			protected.GET("/task/:taskId/vulns", getTaskVulns)
			protected.GET("/task/:taskId/js", getTaskJS)
			protected.GET("/task/:taskId/apis", getTaskAPIs)
			protected.GET("/task/:taskId/protocol-traces", getTaskProtocolTraces)
			protected.GET("/task/:taskId/static-protocol-analysis", getTaskStaticProtocolAnalysis)
			protected.POST("/task/:taskId/protocol-tools/decrypt", decryptProtocolPayload)
			protected.POST("/task/:taskId/protocol-tools/runtime-decrypt", runtimeDecryptProtocolPayload)
			protected.POST("/task/:taskId/protocol-tools/encrypt", encryptProtocolPayload)
			protected.POST("/task/:taskId/protocol-tools/explain", explainProtocolTracePayload)
			protected.GET("/task/:taskId/assets", getTaskAssets)
			protected.POST("/task/:taskId/js/content", getJSContentByPost)
			protected.DELETE("/task/:taskId/tested-urls", clearTaskTestedURLs)
			protected.GET("/task/:taskId/report", exportTaskReport)
			protected.DELETE("/vuln/:vulnId", deleteVuln)
			protected.PATCH("/vuln/:vulnId/status", updateVulnStatus)
			protected.DELETE("/task/:taskId/vuln-clusters/:clusterId", deleteVulnCluster)

			// 受控浏览器会话
			protected.GET("/browser-sessions", getBrowserSessions)
			protected.GET("/browser-sessions/:sessionId", getBrowserSessionDetail)
			protected.POST("/browser-sessions/launch", launchBrowserSession)
			protected.DELETE("/browser-sessions/:sessionId", deleteBrowserSession)

			// 本地任务管理（SQLite）
			protected.GET("/task/records", getTasks)
			protected.POST("/task/save", saveTask)
			protected.POST("/task/update", updateTask)
			protected.POST("/task/delete", deleteTask)

			// 搜索功能
			protected.POST("/search/js", searchJSContent)

			// 自定义JS搜索规则（SQLite）
			protected.GET("/search/js/rules", getJSRules)
			protected.POST("/search/js/rules", createJSRule)
			protected.DELETE("/search/js/rules/:id", deleteJSRule)
		}
	}
}

func generateUUID(c *gin.Context) {
	uid := uuid.New().String()
	c.JSON(200, gin.H{"data": uid})
}

func generateSiteMap(c *gin.Context) {
	var body struct {
		URL string `json:"url"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	// 目标不能为空
	if len(body.URL) == 0 {
		c.JSON(400, gin.H{"error": "url is required"})
		return
	}

	// ---- URL格式校验逻辑 ----
	parsedURL, err := url.Parse(body.URL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		c.JSON(400, gin.H{"error": "invalid url format"})
		return
	}

	// 允许 http/https 开头
	if !strings.HasPrefix(parsedURL.Scheme, "http") {
		c.JSON(400, gin.H{"error": "url must start with http or https"})
		return
	}

	allURLs := crawl.CaptureNetworkURLs(body.URL)
	tree := crawl.BuildElTree(allURLs)
	c.JSON(200, gin.H{"data": tree})
}

type Config struct {
	OpenAI                config.OpenAI        `yaml:"openai" json:"openai"`
	BlackDomain           []string             `yaml:"black-domain" json:"blackDomain"`
	HighRiskRouter        []string             `yaml:"high-risk-router" json:"highRiskRouter"`
	Authentication        []string             `yaml:"authentication" json:"authentication"`
	LearnedAuthentication []string             `json:"learnedAuthentication"`
	Placeholder           map[string]string    `yaml:"placeholder" json:"placeholder"`
	VulnDetection         config.VulnDetection `yaml:"vuln-detection" json:"vulnDetection"`
}

const configPath = "config.yaml"

func getConfig(c *gin.Context) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to read config file"})
		return
	}

	// 读取完整配置
	var fullConfig config.ConfigYAML
	if err := yaml.Unmarshal(data, &fullConfig); err != nil {
		c.JSON(500, gin.H{"error": "failed to parse config file"})
		return
	}

	// 只返回前端需要的配置，排除数据库配置
	learnedAuthentication, err := database.ListEnabledLearnedAuthPatterns()
	if err != nil {
		learnedAuthentication = []string{}
	}

	frontendConfig := Config{
		OpenAI:                fullConfig.OpenAI,
		BlackDomain:           fullConfig.BlackDomain,
		HighRiskRouter:        fullConfig.HighRiskRouter,
		Authentication:        fullConfig.Authentication,
		LearnedAuthentication: learnedAuthentication,
		Placeholder:           fullConfig.Placeholder,
		VulnDetection:         fullConfig.VulnDetection,
	}

	// 若未配置 SQL 注入规则与 payloads，则返回内置默认规则用于展示（不再因 enabled=false 而强制覆盖）
	if len(frontendConfig.VulnDetection.SQLInjection.Rules) == 0 && len(frontendConfig.VulnDetection.SQLInjection.Payloads) == 0 {
		builtinErrorBased := []string{
			"'\"",
			"\"'",
			"')",
			"')--",
			"' OR 1=1--",
			"\" OR 1=1--",
		}
		frontendConfig.VulnDetection.SQLInjection.Rules = []config.SQLiPayloadRule{
			{
				Payloads: builtinErrorBased,
				Type:     "error-based",
				BodyContains: []string{
					"sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite", "database error", "sql error", "query failed",
				},
			},
		}
	}

	// 若前端未配置 LFI 规则与 payloads，则返回内置默认规则用于展示
	if len(frontendConfig.VulnDetection.LFI.Rules) == 0 && len(frontendConfig.VulnDetection.LFI.Payloads) == 0 {
		passwdPayloads := []string{"/etc/passwd", "../../../etc/passwd", "../../../../etc/passwd", "/..%5cetc/passwd", "/..%5c..%5cetc/passwd", "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"}
		hostsPayloads := []string{"/etc/hosts", "../../../../etc/hosts"}
		winPayloads := []string{"..\\..\\..\\..\\windows\\win.ini"}
		frontendConfig.VulnDetection.LFI.Rules = []config.LFIPayloadRule{
			{Payloads: passwdPayloads, MatchType: "regex", Regex: []string{"root:.*:0:0:", "bin:.*:1:1:", "/bin/bash", "/usr/bin/nologin"}},
			{Payloads: hostsPayloads, MatchType: "word", Words: []string{"127.0.0.1", "localhost", "::1"}, Condition: "and"},
			{Payloads: winPayloads, MatchType: "word", Words: []string{"bit app support", "fonts", "extensions"}, Condition: "and"},
		}
	}

	c.JSON(200, gin.H{"data": frontendConfig})
}

func saveConfig(c *gin.Context) {
	var frontendConfig Config
	if err := c.ShouldBindJSON(&frontendConfig); err != nil {
		c.JSON(400, gin.H{"error": "invalid json", "detail": err.Error()})
		return
	}

	// 读取现有配置以保留数据库配置
	data, err := os.ReadFile(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to read config file"})
		return
	}

	var fullConfig config.ConfigYAML
	if err := yaml.Unmarshal(data, &fullConfig); err != nil {
		c.JSON(500, gin.H{"error": "failed to parse config file"})
		return
	}

	// 只更新前端发送的配置字段，保留数据库配置
	fullConfig.OpenAI = frontendConfig.OpenAI
	fullConfig.BlackDomain = frontendConfig.BlackDomain
	fullConfig.HighRiskRouter = frontendConfig.HighRiskRouter
	fullConfig.Authentication = frontendConfig.Authentication
	fullConfig.Placeholder = frontendConfig.Placeholder
	fullConfig.VulnDetection = frontendConfig.VulnDetection

	// 保存更新后的配置
	updatedData, err := yaml.Marshal(&fullConfig)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to marshal config", "detail": err.Error()})
		return
	}

	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		c.JSON(500, gin.H{"error": "failed to write config file", "detail": err.Error(), "path": configPath})
		return
	}

	c.JSON(200, gin.H{"message": "config saved successfully"})
}
