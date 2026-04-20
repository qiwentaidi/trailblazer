package web

import (
	"net/url"
	"os"
	"strings"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/auth"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"

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
			authGroup.POST("/login", auth.LoginHandler)
			authGroup.POST("/logout", auth.LogoutHandler)
		}

		// 需要认证的路由
		protected := api.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			// 用户信息
			protected.GET("/user/info", auth.GetUserInfoHandler)

			// 原有功能路由
			protected.POST("/generate/sitemap", generateSiteMap)
			protected.POST("/scan/start", startScan)
			protected.POST("/scan/stop", stopScan)
			protected.GET("/config", getConfig)
			protected.POST("/config", saveConfig)
			protected.POST("/config/test-es", testESConnection)
			protected.GET("/health/es", checkESHealth)

			// 任务详情查询（ES）
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
			protected.DELETE("/task/:taskId/vuln-clusters/:clusterId", deleteVulnCluster)

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
	OpenAI         config.OpenAI        `yaml:"openai" json:"openai"`
	BlackDomain    []string             `yaml:"black-domain" json:"blackDomain"`
	HighRiskRouter []string             `yaml:"high-risk-router" json:"highRiskRouter"`
	Authentication []string             `yaml:"authentication" json:"authentication"`
	Placeholder    map[string]string    `yaml:"placeholder" json:"placeholder"`
	VulnDetection  config.VulnDetection `yaml:"vuln-detection" json:"vulnDetection"`
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
	frontendConfig := Config{
		OpenAI:         fullConfig.OpenAI,
		BlackDomain:    fullConfig.BlackDomain,
		HighRiskRouter: fullConfig.HighRiskRouter,
		Authentication: fullConfig.Authentication,
		Placeholder:    fullConfig.Placeholder,
		VulnDetection:  fullConfig.VulnDetection,
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
		builtinTimeBased := []string{
			"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
			"' OR SLEEP(5)--",
			"'; WAITFOR DELAY '00:00:05'--",
			"' OR pg_sleep(5)--",
		}
		frontendConfig.VulnDetection.SQLInjection.Rules = []config.SQLiPayloadRule{
			{
				Payloads: builtinErrorBased,
				Type:     "error-based",
				BodyContains: []string{
					"sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite", "database error", "sql error", "query failed",
				},
			},
			{Payloads: builtinTimeBased, Type: "time-based", MinDelayMs: 5000},
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

	// 保存成功后，如果ES配置有效，初始化ES客户端
	if fullConfig.Elasticsearch.Address != "" {
		database.InitESClient(fullConfig.Elasticsearch)
	}

	c.JSON(200, gin.H{"message": "config saved successfully"})
}

// testESConnection 测试ES连接
func testESConnection(c *gin.Context) {
	var body struct {
		Address  string `json:"address"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	// 尝试初始化ES客户端
	esConfig := config.Elasticsearch{
		Address:  body.Address,
		Username: body.Username,
		Password: body.Password,
	}

	database.InitESClient(esConfig)

	// 测试连接
	if database.ESClient == nil {
		c.JSON(500, gin.H{"error": "failed to initialize ES client"})
		return
	}

	res, err := database.ESClient.Info()
	if err != nil {
		c.JSON(500, gin.H{"error": "connection failed", "detail": err.Error()})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		c.JSON(500, gin.H{"error": "ES returned error", "detail": res.String()})
		return
	}

	c.JSON(200, gin.H{"message": "connection successful", "status": res.Status()})
}

// checkESHealth 检查ES连接健康状态
func checkESHealth(c *gin.Context) {
	// 检查ES客户端是否已初始化
	if database.ESClient == nil {
		c.JSON(200, gin.H{
			"connected": false,
			"message":   "ES客户端未初始化",
			"error":     "ES client not initialized",
		})
		return
	}

	// 尝试ping ES服务
	res, err := database.ESClient.Ping()
	if err != nil {
		c.JSON(200, gin.H{
			"connected": false,
			"message":   "ES连接失败",
			"error":     err.Error(),
		})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		c.JSON(200, gin.H{
			"connected": false,
			"message":   "ES服务响应错误",
			"error":     res.String(),
		})
		return
	}

	c.JSON(200, gin.H{
		"connected": true,
		"message":   "ES连接正常",
		"status":    res.Status(),
	})
}
