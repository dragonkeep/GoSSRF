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
	PayloadFile   string            // payload字典文件（-w参数）
	ParamName     string            // 要测试的参数名（-p参数）
	Method        string            // HTTP请求方式（-X参数）
	OOBServer     string            // OOB服务器地址，指定后自动启用OOB测试
	InternalNet   string            // 内网扫描CIDR，例如: 192.168.1.0/24
	Ports         string            // 端口范围，例如: 1-1000 或 80,443,3306,6379
	ScanAll       bool              // 是否扫描所有默认payloads（-all参数）
	Threads       int               // 并发线程数（-t参数）
	Timeout       int               // HTTP请求超时时间（-timeout参数）
	DelayTime     int               // 每次发包间隔时间（毫秒）
	OutputFile    string            // 输出结果到文件（-o参数）
	CustomHeaders map[string]string // 从Header.txt读取的自定义头
	InternalIPs   []string          // 解析后的内网IP列表
	PortList      []int             // 解析后的端口列表
	HeaderFile    string            // Header配置文件路径
}

// ParseFlags 解析命令行参数
func ParseFlags() *Config {
	cfg := &Config{
		CustomHeaders: make(map[string]string),
	}

	flag.StringVar(&cfg.TargetURL, "u", "", "目标URL (例如: http://example.com/api)")
	flag.StringVar(&cfg.Method, "X", "GET", "HTTP请求方式 (GET/POST/PUT等，默认: GET)")
	flag.StringVar(&cfg.ParamName, "p", "", "要测试的参数名 (必须，例如: url)")
	flag.StringVar(&cfg.HeaderFile, "H", "Header.txt", "自定义HTTP头文件路径 (默认: Header.txt)")
	flag.StringVar(&cfg.OutputFile, "o", "", "输出结果到文件")
	flag.StringVar(&cfg.PayloadFile, "w", "", "自定义payload字典文件路径（指定后跳过默认扫描）")
	flag.StringVar(&cfg.OOBServer, "oob", "", "OOB服务器地址 (例如: http://your-server.com:8080，指定后启用OOB测试)")
	flag.StringVar(&cfg.InternalNet, "i", "", "内网扫描目标 (支持: CIDR 192.168.1.0/24 | 单IP 192.168.1.1 | 范围 192.168.1.1-10 | 域名 localhost，指定后默认只扫描这些IP的端口)")
	flag.StringVar(&cfg.Ports, "ports", "", "扫描端口范围 (例如: 1-1000 或 80,443,3306，不指定则扫描默认高危端口)")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "HTTP请求超时时间（秒）")
	flag.IntVar(&cfg.Threads, "t", 10, "并发线程数")
	flag.IntVar(&cfg.DelayTime, "delaytime", 0, "每次发包间隔时间（秒，默认无延迟）")
	flag.BoolVar(&cfg.ScanAll, "all", false, "扫描所有内置字典")

	// 自定义帮助信息输出顺序
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])

		// 按自定义顺序输出参数
		order := []string{"u", "X", "p", "H", "o", "w", "oob", "i", "ports", "timeout", "t", "delaytime", "all"}
		for _, name := range order {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(flag.CommandLine.Output(), "  -%s", f.Name)
				if f.DefValue != "" && f.DefValue != "false" {
					fmt.Fprintf(flag.CommandLine.Output(), " %s", f.DefValue)
				}
				fmt.Fprintf(flag.CommandLine.Output(), "\n    \t%s\n", f.Usage)
			}
		}
	}

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

	// 验证OOB服务器地址格式（如果指定了）
	if c.OOBServer != "" {
		if _, err := url.Parse(c.OOBServer); err != nil {
			return fmt.Errorf("无效的OOB服务器地址: %v", err)
		}
	}

	// 解析内网IP（支持CIDR、单个IP、IP范围）
	if c.InternalNet != "" {
		ips, err := parseInternalIPs(c.InternalNet)
		if err != nil {
			return fmt.Errorf("无效的IP格式: %v", err)
		}
		c.InternalIPs = ips
	}

	// 解析端口范围
	if c.Ports != "" {
		ports, err := parsePorts(c.Ports)
		if err != nil {
			return fmt.Errorf("无效的端口范围: %v", err)
		}
		c.PortList = ports
	}

	// 加载自定义Headers
	if c.HeaderFile != "" {
		if err := c.loadHeaders(); err != nil {
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

// parseInternalIPs 解析内网IP（支持CIDR、单个IP、IP范围、主机名/域名）
func parseInternalIPs(ipStr string) ([]string, error) {
	var ips []string

	// 去除首尾空白
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return nil, fmt.Errorf("目标地址不能为空")
	}

	// 检查是否包含范围符号 "-"（但不是IPv6地址）
	if strings.Contains(ipStr, "-") && !strings.Contains(ipStr, "/") {
		// IP范围格式: 192.168.1.1-10
		return parseIPRange(ipStr)
	}

	// 检查是否是CIDR格式
	if strings.Contains(ipStr, "/") {
		// CIDR格式: 192.168.1.0/24
		return parseCIDR(ipStr)
	}

	ip := net.ParseIP(ipStr)
	if ip != nil {
		// 是有效的IP地址格式
		ips = append(ips, ipStr)
		return ips, nil
	}
	validHostname := true
	for _, ch := range ipStr {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_') {
			validHostname = false
			break
		}
	}

	if !validHostname {
		return nil, fmt.Errorf("无效的目标地址格式: %s (仅支持字母、数字、点、中划线、下划线)", ipStr)
	}

	// 直接返回主机名，不解析（由目标服务器内网DNS解析）
	ips = append(ips, ipStr)
	return ips, nil
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

	return ips, nil
}

// parseIPRange 解析IP范围（格式: 192.168.1.1-10 或 192.168.1.1-192.168.1.10）
func parseIPRange(rangeStr string) ([]string, error) {
	var ips []string

	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的IP范围格式: %s", rangeStr)
	}

	startIPStr := strings.TrimSpace(parts[0])
	endIPStr := strings.TrimSpace(parts[1])

	// 解析起始IP
	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, fmt.Errorf("无效的起始IP: %s", startIPStr)
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("仅支持IPv4地址: %s", startIPStr)
	}

	// 处理结束IP
	var endIP net.IP
	if strings.Contains(endIPStr, ".") {
		// 完整IP格式: 192.168.1.1-192.168.1.10
		endIP = net.ParseIP(endIPStr)
		if endIP == nil {
			return nil, fmt.Errorf("无效的结束IP: %s", endIPStr)
		}
		endIP = endIP.To4()
		if endIP == nil {
			return nil, fmt.Errorf("仅支持IPv4地址: %s", endIPStr)
		}
	} else {
		// 简写格式: 192.168.1.1-10（表示192.168.1.1到192.168.1.10）
		var lastOctet int
		if _, err := fmt.Sscanf(endIPStr, "%d", &lastOctet); err != nil {
			return nil, fmt.Errorf("无效的结束IP格式: %s", endIPStr)
		}
		if lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("IP最后一位必须在0-255之间: %d", lastOctet)
		}

		// 构造完整的结束IP
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(lastOctet)
	}

	// 验证起始IP不大于结束IP
	if compareIP(startIP, endIP) > 0 {
		return nil, fmt.Errorf("起始IP不能大于结束IP: %s-%s", startIPStr, endIP.String())
	}

	// 生成IP范围
	currentIP := make(net.IP, len(startIP))
	copy(currentIP, startIP)

	for {
		ips = append(ips, currentIP.String())
		if compareIP(currentIP, endIP) >= 0 {
			break
		}
		inc(currentIP)
	}

	return ips, nil
}

// compareIP 比较两个IP地址
// 返回: -1 (ip1 < ip2), 0 (ip1 == ip2), 1 (ip1 > ip2)
func compareIP(ip1, ip2 net.IP) int {
	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
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

// parsePorts 解析端口范围
// 支持格式: "80,443,3306" 或 "1-1000" 或混合 "80,443,1000-2000"
func parsePorts(portStr string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// 检查是否是范围 (例如: 1-1000)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围格式: %s", part)
			}

			var start, end int
			if _, err := fmt.Sscanf(rangeParts[0], "%d", &start); err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", rangeParts[0])
			}
			if _, err := fmt.Sscanf(rangeParts[1], "%d", &end); err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", rangeParts[1])
			}

			if start < 1 || start > 65535 || end < 1 || end > 65535 {
				return nil, fmt.Errorf("端口号必须在1-65535之间: %s", part)
			}
			if start > end {
				return nil, fmt.Errorf("起始端口不能大于结束端口: %s", part)
			}

			for port := start; port <= end; port++ {
				if !seen[port] {
					ports = append(ports, port)
					seen[port] = true
				}
			}
		} else {
			// 单个端口
			var port int
			if _, err := fmt.Sscanf(part, "%d", &port); err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号必须在1-65535之间: %d", port)
			}

			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	return ports, nil
}

// ShouldScanOOB 判断是否应该进行OOB扫描
func (c *Config) ShouldScanOOB() bool {
	return c.OOBServer != ""
}
