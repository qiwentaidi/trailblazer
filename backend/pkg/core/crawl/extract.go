package crawl

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
)

type Extract struct{}

var (
	regJS  []*regexp.Regexp
	JsLink = []string{
		"(https{0,1}:[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)",
		"[\"'‘“`]\\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)",
		"=\\s{0,6}[\",',’,”]{0,1}\\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\\+.~#?&//=]{3}[.]js)",
	}
)

func init() {
	for _, reg := range JsLink {
		regJS = append(regJS, regexp.MustCompile(reg))
	}
}

// 通过主页提取静态JS
func (e *Extract) StaticJSLink(url string) []string {
	var staticJsLinks []string
	resp, err := clients.SimpleGet(url, clients.NewRestyClient(nil, true))
	if err != nil {
		fmt.Printf("[错误] %s 提取静态JS失败，错误原因: %v\n", url, err)
		return staticJsLinks
	}
	content := string(resp.Body())
	for _, reg := range regJS {
		for _, item := range reg.FindAllString(content, -1) {
			// 去除所有干扰符号
			item = strings.ReplaceAll(item, " ", "")
			item = strings.ReplaceAll(item, "=", "")
			item = strings.ReplaceAll(item, "'", "")
			item = strings.ReplaceAll(item, "\"", "")
			item = strings.Trim(item, ".")
			staticJsLinks = append(staticJsLinks, item)
		}
	}
	return staticJsLinks
}

type NetworkLinks struct {
	ALL            []string
	Classification struct {
		APIRoot  []string // APi根路径， eg: http://127.0.0.1:8080/api/
		JS       []string
		APIRoute []string // 获取完整加载的API链接
	}
}

// ClassifyLinks 将已捕获的链接进行分类（新增：支持外部传入链接集合）
func (e *Extract) ClassifyLinks(links []string, blackDomain []string) NetworkLinks {
	networkLinks := NetworkLinks{}
	filter := &Filter{}
	networkLinks.ALL = links
	networkLinks.Classification.JS = filter.JSLinks(links)
	apis := filter.Api(links, blackDomain)
	for _, item := range apis {
		u, err := url.Parse(item)
		if err != nil {
			continue
		}
		if u.RequestURI() != "/" {
			networkLinks.Classification.APIRoute = append(networkLinks.Classification.APIRoute, u.String())
		}
		rootApi, err := e.ExtractAPIRoots(item)
		if err != nil {
			continue
		}
		networkLinks.Classification.APIRoot = append(networkLinks.Classification.APIRoot, rootApi...)
	}
	// 去重
	networkLinks.Classification.APIRoot = arrayutil.RemoveDuplicates(networkLinks.Classification.APIRoot)
	return networkLinks
}

// ExtractAPIRoots 提取 API Root（只取前 1~2 级，带完整 URL）
func (e *Extract) ExtractAPIRoots(rawURL string) ([]string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	cleanPath := path.Clean(parsed.Path)
	if cleanPath == "/" {
		return nil, nil
	}

	parts := strings.Split(strings.Trim(cleanPath, "/"), "/")

	var roots []string
	// 只取前 1~2 级
	for i := 1; i <= len(parts) && i <= 2; i++ {
		root := "/" + strings.Join(parts[:i], "/") + "/"
		fullURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, root)
		roots = append(roots, fullURL)
	}

	return roots, nil
}
