package web

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/webassets"
	"gopkg.in/yaml.v3"
)

type ServerOptions struct {
	ConfigPath     string
	DatabasePath   string
	FrontendDevURL string
	Host           string
	Port           int
}

func Run(options ServerOptions) error {
	if options.ConfigPath == "" {
		options.ConfigPath = "config.yaml"
	}
	if options.DatabasePath == "" {
		options.DatabasePath = "tasks.db"
	}
	if err := database.InitSQLite(options.DatabasePath); err != nil {
		return fmt.Errorf("initialize SQLite: %w", err)
	}

	webConfig := config.WebConfig{Host: "0.0.0.0", Port: 9092}
	if data, err := os.ReadFile(options.ConfigPath); err == nil {
		var cfg config.ConfigYAML
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse web config: %w", err)
		}
		if cfg.Web.Port > 0 {
			webConfig.Port = cfg.Web.Port
		}
		if cfg.Web.Host != "" {
			webConfig.Host = cfg.Web.Host
		}
		webConfig.Debug = cfg.Web.Debug
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read web config: %w", err)
	}
	if options.Host != "" {
		webConfig.Host = options.Host
	}
	if options.Port > 0 {
		webConfig.Port = options.Port
	}

	gin.SetMode(gin.ReleaseMode)
	if webConfig.Debug {
		gin.SetMode(gin.DebugMode)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"*"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	corsConfig.AllowCredentials = true
	r.Use(cors.New(corsConfig))
	RegisterRoutes(r)
	if err := webassets.Register(r, options.FrontendDevURL); err != nil {
		return fmt.Errorf("register frontend: %w", err)
	}

	address := fmt.Sprintf("%s:%d", webConfig.Host, webConfig.Port)
	log.Printf("Web 服务启动中，监听地址: %s", address)
	return r.Run(address)
}
