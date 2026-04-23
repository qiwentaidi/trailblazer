package webassets

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed all:dist
var embeddedDistFS embed.FS

var (
	assetFS   fs.FS
	indexHTML []byte
)

func Register(r *gin.Engine, frontendDevURL string) error {
	if strings.TrimSpace(frontendDevURL) != "" {
		return registerDevProxy(r, frontendDevURL)
	}

	resolvedFS, index, source, err := resolveAssets()
	if err != nil {
		return err
	}

	assetFS = resolvedFS
	indexHTML = index

	fileServer := http.FileServer(http.FS(assetFS))
	r.NoRoute(func(c *gin.Context) {
		urlPath := c.Request.URL.Path
		if strings.HasPrefix(urlPath, "/api") {
			c.Status(http.StatusNotFound)
			return
		}

		cleanPath := path.Clean(urlPath)
		cleanPath = strings.TrimSuffix(cleanPath, "/")
		if cleanPath == "" || cleanPath == "/" {
			serveHTML(c, indexHTML)
			return
		}

		cleanPath = strings.TrimPrefix(cleanPath, "/")
		if isFile(cleanPath) {
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		htmlPath := cleanPath + ".html"
		if content, err := fs.ReadFile(assetFS, htmlPath); err == nil {
			serveHTML(c, content)
			return
		}

		indexPath := cleanPath + "/index.html"
		if content, err := fs.ReadFile(assetFS, indexPath); err == nil {
			serveHTML(c, content)
			return
		}

		serveHTML(c, indexHTML)
	})

	fmt.Printf("[INFO] Frontend assets source: %s\n", source)
	return nil
}

func registerDevProxy(r *gin.Engine, frontendDevURL string) error {
	target, err := url.Parse(strings.TrimSpace(frontendDevURL))
	if err != nil {
		return fmt.Errorf("invalid frontend dev url: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.Status(http.StatusNotFound)
			return
		}
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	fmt.Printf("[INFO] Frontend assets source: dev proxy -> %s\n", target.String())
	return nil
}

func resolveAssets() (fs.FS, []byte, string, error) {
	if subFS, index, err := loadEmbeddedAssets(); err == nil {
		return subFS, index, "embedded backend/webassets/dist", nil
	}

	candidates := []string{
		"webassets/dist",
		"./dist",
		"../frontend-admin/dist",
		"frontend-admin/dist",
	}
	for _, candidate := range candidates {
		subFS := os.DirFS(candidate)
		index, err := fs.ReadFile(subFS, "index.html")
		if err == nil {
			return subFS, index, candidate, nil
		}
	}

	return nil, nil, "", fmt.Errorf(
		"frontend assets not found: build frontend and copy it into backend/webassets/dist, or keep frontend-admin/dist available locally",
	)
}

func loadEmbeddedAssets() (fs.FS, []byte, error) {
	subFS, err := fs.Sub(embeddedDistFS, "dist")
	if err != nil {
		return nil, nil, err
	}

	index, err := fs.ReadFile(subFS, "index.html")
	if err != nil {
		return nil, nil, err
	}

	return subFS, index, nil
}

func isFile(filePath string) bool {
	if assetFS == nil {
		return false
	}

	f, err := assetFS.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func serveHTML(c *gin.Context, content []byte) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Writer.WriteHeader(http.StatusOK)
	_, _ = c.Writer.Write(content)
}
