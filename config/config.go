package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// Config 配置结构
type Config struct {
	TargetURL     string
	PayloadFile   string // payload字典文件（-w参数）
	ParamName     string // 要测试的参数名（-p参数）
	Method        string // HTTP请求方式（-X参数）
	OOBServer     string
	InternalNet   string // 内网扫描CIDR，例如: 192.168.1.0/24
	Threads       int
	Timeout       int
	Verbose       bool
	OutputFile    string
	ScanPorts     bool
	ScanFile      bool
	ScanOOB       bool
	CustomHeaders map[string]string // 从Header.yaml读取的自定义头
	InternalIPs   []string          // 解析后的内网IP列表
	HeaderFile    string            // Header配置文件路径
}

// ParseFlags 解析命令行参数
func ParseFlags() *Config {
	cfg := &Config{
		CustomHeaders: make(map[string]string),
	}

	flag.StringVar(&cfg.TargetURL, "u", "", "目标URL (例如: http://example.com/api)")
	flag.StringVar(&cfg.ParamName, "p", "", "要测试的参数名 (必须，例如: url)")
	flag.StringVar(&cfg.Method, "X", "GET", "HTTP请求方式 (GET/POST/PUT等，默认: GET)")
	flag.StringVar(&cfg.PayloadFile, "w", "", "自定义payload字典文件路径（可选）")
	flag.StringVar(&cfg.OOBServer, "oob", "", "OOB服务器地址 (例如: http://your-server.com:8080)")
	flag.StringVar(&cfg.InternalNet, "i", "", "内网扫描CIDR (例如: 192.168.1.0/24，不指定则只扫描127.0.0.1)")
	flag.StringVar(&cfg.HeaderFile, "H", "Header.yaml", "自定义HTTP头文件路径 (默认: Header.yaml)")
	flag.IntVar(&cfg.Threads, "t", 10, "并发线程数")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "HTTP请求超时时间（秒）")
	flag.BoolVar(&cfg.Verbose, "v", false, "详细输出模式")
	flag.StringVar(&cfg.OutputFile, "o", "", "输出结果到文件")
	flag.BoolVar(&cfg.ScanPorts, "scan-ports", true, "扫描内网端口（默认启用，默认只扫描127.0.0.1）")
	flag.BoolVar(&cfg.ScanFile, "scan-file", true, "测试文件读取（file协议，默认启用）")
	flag.BoolVar(&cfg.ScanOOB, "scan-oob", false, "测试OOB回连（需要-oob参数）")

	return cfg
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.TargetURL == "" {
		return errors.New("必须指定目标URL (-u)")
	}

	// 验证URL格式
	_, err := url.Parse(c.TargetURL)
	if err != nil {
		return fmt.Errorf("无效的URL格式: %v", err)
	}

	// 必须指定参数名
	if c.ParamName == "" {
		return errors.New("必须指定要测试的参数名 (-p)")
	}

	// 验证HTTP方法
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}
	c.Method = strings.ToUpper(c.Method)
	if !validMethods[c.Method] {
		return fmt.Errorf("不支持的HTTP方法: %s", c.Method)
	}

	// 如果启用OOB扫描，必须指定OOB服务器
	if c.ScanOOB && c.OOBServer == "" {
		return errors.New("启用OOB扫描时必须指定OOB服务器地址 (-oob)")
	}

	// 验证OOB服务器地址格式
	if c.OOBServer != "" {
		if _, err := url.Parse(c.OOBServer); err != nil {
			return fmt.Errorf("无效的OOB服务器地址: %v", err)
		}
	}

	// 解析内网CIDR
	if c.InternalNet != "" {
		ips, err := parseCIDR(c.InternalNet)
		if err != nil {
			return fmt.Errorf("无效的CIDR格式: %v", err)
		}
		c.InternalIPs = ips
	}

	// 读取自定义Header文件
	if err := c.loadHeaders(); err != nil {
		// Header文件不存在不是致命错误，只是警告
		if c.Verbose {
			fmt.Printf("[*] Header文件读取失败，使用默认Header: %v\n", err)
		}
	}

	return nil
}

// loadHeaders 从文件加载自定义HTTP头（Burp格式：每行一个header，格式：Header-Name: Value）
func (c *Config) loadHeaders() error {
	// 检查文件是否存在
	if _, err := os.Stat(c.HeaderFile); os.IsNotExist(err) {
		return fmt.Errorf("header文件不存在: %s", c.HeaderFile)
	}

	// 读取文件内容
	data, err := os.ReadFile(c.HeaderFile)
	if err != nil {
		return fmt.Errorf("读取header文件失败: %v", err)
	}

	// 解析Burp格式（每行一个header）
	headers := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 查找第一个冒号的位置
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue // 跳过无效行
		}

		// 分割 header 名称和值
		headerName := strings.TrimSpace(line[:colonIdx])
		headerValue := strings.TrimSpace(line[colonIdx+1:])

		if headerName != "" {
			headers[headerName] = headerValue
		}
	}

	c.CustomHeaders = headers
	return nil
}

// Print 打印配置信息
func (c *Config) Print() {
	// 不打印配置信息，保持简洁
}

// GetParams 获取要测试的参数（现在是单个参数）
func (c *Config) GetParams() map[string]string {
	params := make(map[string]string)
	params[c.ParamName] = "test" // 默认值，实际会被payload替换
	return params
}

// parseCIDR 解析CIDR并返回IP列表
func parseCIDR(cidr string) ([]string, error) {
	var ips []string

	// 解析CIDR
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// 遍历网段中的所有IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// 移除网络地址和广播地址（对于/24等子网）
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	// 限制最大IP数量，避免扫描过大网段导致性能问题（已注释，用户要求移除限制）
	// maxIPs := 254
	// if len(ips) > maxIPs {
	// 	red := Colors(ColorRed)
	// 	red.Printf("[!] 警告: CIDR包含%d个IP，为避免扫描时间过长，仅扫描前%d个\n", len(ips), maxIPs)
	// 	ips = ips[:maxIPs]
	// }

	return ips, nil
}

// inc IP地址递增
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
