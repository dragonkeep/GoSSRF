package detector

import (
	"crypto/tls"
	"fmt"
	"gosssrf-client/config"
	"gosssrf-client/payloads"
	"io"
	"net/http"
	"strings"
	"time"
)

// Detector 检测器
type Detector struct {
	config *config.Config
	client *http.Client
}

// NewDetector 创建检测器
func NewDetector(cfg *config.Config) *Detector {
	// 创建HTTP客户端
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 不跟随重定向
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略证书验证
			},
		},
	}

	return &Detector{
		config: cfg,
		client: client,
	}
}

// DetectWithMethod 使用指定HTTP方法检测是否存在SSRF漏洞
// 返回: vulnerable, evidence, statusCode, responseLen, responseTime, errorMsg
func (d *Detector) DetectWithMethod(method, testURL, body string, payload payloads.Payload) (bool, string, int, int, int64, string) {
	startTime := time.Now()

	// 创建请求
	var req *http.Request
	var err error

	if body != "" {
		req, err = http.NewRequest(method, testURL, strings.NewReader(body))
		if err != nil {
			return false, "", 0, 0, 0, fmt.Sprintf("创建请求失败: %v", err)
		}
		// POST请求需要设置Content-Type
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, testURL, nil)
		if err != nil {
			return false, "", 0, 0, 0, fmt.Sprintf("创建请求失败: %v", err)
		}
	}

	// 添加自定义Header
	for key, value := range d.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := d.client.Do(req)
	if err != nil {
		// 返回错误信息
		if strings.Contains(err.Error(), "connection refused") {
			return false, "", 0, 0, 0, "连接被拒绝"
		}
		if strings.Contains(err.Error(), "timeout") {
			return false, "", 0, 0, 0, "请求超时"
		}
		if strings.Contains(err.Error(), "no such host") {
			return false, "", 0, 0, 0, "域名解析失败"
		}
		return false, "", 0, 0, 0, fmt.Sprintf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 计算响应时间
	responseTime := time.Since(startTime).Milliseconds()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", resp.StatusCode, 0, responseTime, "读取响应失败"
	}

	bodyStr := string(respBody)
	responseLen := len(respBody)

	// 检测SSRF特征
	vulnerable, evidence := d.analyzeResponse(resp, bodyStr, payload)

	return vulnerable, evidence, resp.StatusCode, responseLen, responseTime, ""
}

// Detect 检测是否存在SSRF漏洞
// 返回: vulnerable, evidence, statusCode, responseLen, responseTime
func (d *Detector) Detect(testURL string, payload payloads.Payload) (bool, string, int, int, int64) {
	startTime := time.Now()

	// 发送请求
	resp, err := d.client.Get(testURL)
	if err != nil {
		// 某些情况下，错误本身就是证据（例如连接被拒绝说明端口存在）
		if strings.Contains(err.Error(), "connection refused") {
			return false, "连接被拒绝（端口可能关闭）", 0, 0, 0
		}
		if strings.Contains(err.Error(), "timeout") {
			// 超时可能意味着端口开放但服务无响应
			return false, "请求超时", 0, 0, 0
		}
		return false, "", 0, 0, 0
	}
	defer resp.Body.Close()

	// 计算响应时间
	responseTime := time.Since(startTime).Milliseconds()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", resp.StatusCode, 0, responseTime
	}

	bodyStr := string(body)
	responseLen := len(body)

	// 检测SSRF特征
	vulnerable, evidence := d.analyzeResponse(resp, bodyStr, payload)

	return vulnerable, evidence, resp.StatusCode, responseLen, responseTime
}

// analyzeResponse 分析响应判断是否存在SSRF
func (d *Detector) analyzeResponse(resp *http.Response, body string, payload payloads.Payload) (bool, string) {
	// 1. 检查关键字（最可靠的证据）
	if len(payload.Keywords) > 0 {
		for _, keyword := range payload.Keywords {
			if strings.Contains(body, keyword) {
				return true, fmt.Sprintf("响应中包含特征关键字: %s", keyword)
			}
		}
	}

	// 2. 检查状态码
	// 200状态码通常意味着成功访问了内网资源
	if resp.StatusCode == 200 {
		// 对于端口扫描，200状态码是重要证据
		if payload.Type == "端口扫描" && len(body) > 0 {
			// 检查是否返回了HTTP服务的响应
			if strings.Contains(body, "HTTP/") ||
				strings.Contains(body, "Server:") ||
				strings.Contains(body, "<html") {
				return true, "成功访问内网HTTP服务"
			}

			// 检查服务特征
			if containsAny(body, []string{"redis", "mysql", "MongoDB", "Elasticsearch"}) {
				return true, "检测到内网服务特征"
			}
		}

		// 对于文件读取，检查文件内容特征
		if payload.Type == "文件读取" {
			if len(body) > 50 { // 文件内容通常有一定长度
				return true, fmt.Sprintf("可能成功读取文件，响应长度: %d", len(body))
			}
		}
	}

	// 3. 检查响应长度异常
	// 如果响应长度大于某个阈值，可能意味着成功读取了内网资源
	if len(body) > 200 {
		// 检查是否包含敏感信息
		sensitiveKeywords := []string{
			"root:", "password", "secret", "token", "api_key",
			"localhost", "127.0.0.1", "private", "internal",
			"AccessKeyId", "SecretAccessKey",
		}

		for _, keyword := range sensitiveKeywords {
			if strings.Contains(strings.ToLower(body), strings.ToLower(keyword)) {
				return true, fmt.Sprintf("响应中包含敏感信息: %s", keyword)
			}
		}
	}

	// 4. 检查特殊状态码
	// 某些状态码可能表示内网资源的存在
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true, fmt.Sprintf("状态码 %d - 资源存在但需要认证", resp.StatusCode)
	}

	// 5. 检查响应头
	// 某些响应头可能泄露内网信息
	if server := resp.Header.Get("Server"); server != "" {
		if containsAny(server, []string{"Redis", "MySQL", "nginx", "Apache", "Microsoft"}) {
			return true, fmt.Sprintf("Server头泄露内网服务信息: %s", server)
		}
	}

	// 6. 对于OOB类型，需要检查回连服务器
	if payload.Type == "OOB检测" {
		// 这里只是发送请求，实际需要在OOB服务器上查看是否收到回连
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return true, "OOB请求已发送，请检查OOB服务器是否收到回连"
		}
	}

	return false, ""
}

// containsAny 检查字符串是否包含列表中的任意一个
func containsAny(s string, substrs []string) bool {
	lowerS := strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(lowerS, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
