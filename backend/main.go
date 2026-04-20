package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/auth"
	"trailblazer/pkg/core/database"
	cliscan "trailblazer/pkg/lib"
	"trailblazer/pkg/web"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

func main() {
	config.Banner()

	app := &cli.App{
		Name:        "trailblazer",
		Usage:       "Web安全扫描工具",
		Description: "TrailBlazer是一个功能强大的Web安全扫描工具，支持Web界面和命令行两种模式",
		Commands: []*cli.Command{
			{
				Name:        "cli",
				Aliases:     []string{"c"},
				Usage:       "运行CLI模式（扫描并输出JSON结果）",
				Description: "CLI模式用于命令行扫描，无需数据库，结果直接输出为JSON格式",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "urls",
						Aliases: []string{"u"},
						Usage:   "要扫描的URL列表，多个URL用逗号分隔",
					},
					&cli.StringFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "包含URL列表的文件路径（每行一个URL）",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "输出JSON文件路径（可选，默认输出到标准输出）",
					},
					&cli.StringFlag{
						Name:  "config",
						Usage: "配置文件路径",
						Value: "config.yaml",
					},
				},
				Action: runCLIMode,
			},
			{
				Name:        "web",
				Aliases:     []string{"w"},
				Usage:       "运行Web模式（启动Web服务器）",
				Description: "Web模式启动一个Web服务器，提供图形化界面进行扫描任务管理",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "config",
						Usage: "配置文件路径",
						Value: "config.yaml",
					},
				},
				Action: runWebMode,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("错误: %v", err)
	}
}

// runCLIMode 运行CLI模式
func runCLIMode(c *cli.Context) error {
	var urlList []string

	// 从命令行参数读取URL
	urls := c.String("urls")
	if urls != "" {
		urlsFromFlag := strings.Split(urls, ",")
		for _, url := range urlsFromFlag {
			url = strings.TrimSpace(url)
			if url != "" {
				urlList = append(urlList, url)
			}
		}
	}

	// 从文件读取URL
	filePath := c.String("file")
	if filePath != "" {
		fileURLs, err := readURLsFromFile(filePath)
		if err != nil {
			return fmt.Errorf("读取文件失败: %w", err)
		}
		urlList = append(urlList, fileURLs...)
	}

	// 检查是否至少提供了一个URL
	if len(urlList) == 0 {
		return fmt.Errorf("错误: CLI模式需要指定 -urls 参数或 -file 参数（至少一个）")
	}

	// 去重
	urlList = removeDuplicateURLs(urlList)

	output := c.String("output")
	configPath := c.String("config")

	fmt.Printf("[INFO] 启动CLI扫描模式\n")
	fmt.Printf("[INFO] 扫描目标数量: %d\n", len(urlList))
	fmt.Printf("[INFO] 配置文件: %s\n", configPath)
	if output != "" {
		fmt.Printf("[INFO] 输出文件: %s\n", output)
	} else {
		fmt.Printf("[INFO] 输出到标准输出\n")
	}

	if err := cliscan.PerformScanWithConfigFile(urlList, configPath, output); err != nil {
		return fmt.Errorf("扫描失败: %w", err)
	}

	return nil
}

// readURLsFromFile 从文件中读取URL列表（每行一个URL）
func readURLsFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var urls []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 跳过空行和注释行（以#开头）
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	return urls, nil
}

// removeDuplicateURLs 移除重复的URL
func removeDuplicateURLs(urls []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			result = append(result, url)
		}
	}
	return result
}

// runWebMode 运行Web模式
func runWebMode(c *cli.Context) error {
	configPath := c.String("config")

	// 初始化SQLite
	if err := database.InitSQLite("./tasks.db"); err != nil {
		log.Printf("Warning: Failed to init SQLite: %v", err)
	}

	// 初始化默认用户
	if err := auth.InitializeDefaultUser(); err != nil {
		log.Printf("Warning: Failed to initialize default user: %v", err)
	}

	// 加载配置文件
	var webConfig config.WebConfig
	webConfig.Port = 9092      // 默认端口
	webConfig.Host = "0.0.0.0" // 默认主机

	if data, err := os.ReadFile(configPath); err == nil {
		var cfg config.ConfigYAML
		if err := yaml.Unmarshal(data, &cfg); err == nil {
			// 设置web配置
			if cfg.Web.Port > 0 {
				webConfig.Port = cfg.Web.Port
			}
			if cfg.Web.Host != "" {
				webConfig.Host = cfg.Web.Host
			}
			webConfig.Debug = cfg.Web.Debug

			// 初始化ES
			if cfg.Elasticsearch.Address != "" {
				database.InitESClient(cfg.Elasticsearch)
				log.Println("Elasticsearch client initialized from config")
			}
		}
	}

	r := gin.New()
	r.Use(gin.Recovery())

	r.Static("/assets", "./dist/assets")         // 静态资源
	r.StaticFile("/", "./dist/index.html")       // 首页
	r.StaticFile("/icon.svg", "./dist/icon.svg") // 网站图标

	// 配置 CORS
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"*"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	corsConfig.AllowCredentials = true
	r.Use(cors.New(corsConfig))
	web.RegisterRoutes(r)

	// 设置Gin模式
	if webConfig.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 启动服务器
	serverAddr := fmt.Sprintf("%s:%d", webConfig.Host, webConfig.Port)
	log.Printf("Server starting on %s...", serverAddr)
	if err := r.Run(serverAddr); err != nil {
		return fmt.Errorf("Failed to start server: %w", err)
	}

	return nil
}
