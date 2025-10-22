package scanner

import (
	"bufio"
	"fmt"
	"gosssrf-client/config"
	"gosssrf-client/detector"
	"gosssrf-client/payloads"
	"os"
	"strings"
	"sync"
)

// ScanResult 扫描结果
type ScanResult struct {
	URL          string
	Parameter    string
	Payload      string
	PayloadType  string
	StatusCode   int
	ResponseLen  int
	ResponseTime int64
	Vulnerable   bool
	Evidence     string
	Severity     string
}

// ScanManager 扫描管理器
type ScanManager struct {
	config       *config.Config
	detector     *detector.Detector
	outputMux    sync.Mutex
	outputFile   *os.File
	vulnCount    int
	vulnCountMux sync.Mutex
}

// NewScanManager 创建扫描管理器
func NewScanManager(cfg *config.Config, det *detector.Detector, outputFile *os.File) *ScanManager {
	return &ScanManager{
		config:     cfg,
		detector:   det,
		outputFile: outputFile,
		vulnCount:  0,
	}
}

// RunScan 执行扫描，返回发现的漏洞数量
func (sm *ScanManager) RunScan() int {
	// 获取要测试的参数
	params := sm.config.GetParams()

	// 如果指定了字典文件，只使用字典文件扫描
	if sm.config.PayloadFile != "" {
		sm.scanWithCustomDict(params)
		return sm.vulnCount
	}

	// 否则使用默认扫描
	// 1. 端口扫描（总是启用）
	sm.scanPorts(params)

	// 2. 文件读取测试（根据配置决定是否启用）
	if sm.config.ShouldScanDefaultPayloads() {
		sm.scanFileRead(params)
	}

	// 3. OOB测试（指定-oob参数后启用，且满足ShouldScanDefaultPayloads条件）
	if sm.config.ShouldScanOOB() && sm.config.ShouldScanDefaultPayloads() {
		sm.scanOOB(params)
	}

	return sm.vulnCount
}

// scanPorts 扫描端口
func (sm *ScanManager) scanPorts(params map[string]string) {
	var wg sync.WaitGroup

	// 如果指定了字典文件，则不使用默认payload
	if sm.config.PayloadFile != "" {
		return
	}

	// 获取端口扫描payload（传入内网IP列表、自定义端口列表、是否包含云元数据）
	portPayloads := payloads.GetPortScanPayloads(sm.config.InternalIPs, sm.config.PortList, sm.config.ShouldScanDefaultPayloads())
	semaphore := make(chan struct{}, sm.config.Threads)

	for paramName := range params {
		for _, payload := range portPayloads {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(param string, pl payloads.Payload) {
				defer func() {
					<-semaphore
					wg.Done()
				}()

				sm.testPayload(param, pl)
			}(paramName, payload)
		}
	}

	wg.Wait()
}

// scanFileRead 文件读取测试
func (sm *ScanManager) scanFileRead(params map[string]string) {
	var wg sync.WaitGroup

	// 如果指定了字典文件，则不使用默认payload
	if sm.config.PayloadFile != "" {
		return
	}

	// 获取文件读取payload
	filePayloads := payloads.GetFileReadPayloads()
	semaphore := make(chan struct{}, sm.config.Threads)

	for paramName := range params {
		for _, payload := range filePayloads {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(param string, pl payloads.Payload) {
				defer func() {
					<-semaphore
					wg.Done()
				}()

				sm.testPayload(param, pl)
			}(paramName, payload)
		}
	}

	wg.Wait()
}

// scanOOB OOB测试
func (sm *ScanManager) scanOOB(params map[string]string) {
	var wg sync.WaitGroup

	// 获取OOB payload
	oobPayloads := payloads.GetOOBPayloads(sm.config.OOBServer)
	semaphore := make(chan struct{}, sm.config.Threads)

	for paramName := range params {
		for _, payload := range oobPayloads {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(param string, pl payloads.Payload) {
				defer func() {
					<-semaphore
					wg.Done()
				}()

				sm.testPayload(param, pl)
			}(paramName, payload)
		}
	}

	wg.Wait()
}

// testPayload 测试单个payload
func (sm *ScanManager) testPayload(param string, payload payloads.Payload) {
	// 构造测试请求
	testURL, body, err := buildTestRequest(sm.config.Method, sm.config.TargetURL, param, payload.Value)
	if err != nil {
		return
	}

	// 打印测试信息（使用互斥锁保护输出顺序）
	sm.outputMux.Lock()
	testMsg := fmt.Sprintf("[%s] 正在测试 %s\n", sm.config.Method, payload.Value)
	fmt.Print(testMsg)
	if sm.outputFile != nil {
		sm.outputFile.WriteString(testMsg)
	}
	sm.outputMux.Unlock()

	// 发送请求并检测
	vulnerable, _, _, _, _, errMsg := sm.detector.DetectWithMethod(
		sm.config.Method, testURL, body, payload)

	// 输出结果（使用互斥锁保护输出顺序）
	sm.outputMux.Lock()
	if errMsg != "" {
		// 红色输出错误（文件中保存纯文本）
		red := config.Colors(config.ColorRed)
		red.Printf("[%s] %s Error: %s\n", sm.config.Method, testURL, errMsg)
		if sm.outputFile != nil {
			errOutput := fmt.Sprintf("[%s] %s Error: %s\n", sm.config.Method, testURL, errMsg)
			sm.outputFile.WriteString(errOutput)
		}
	}

	if vulnerable {
		// 绿色输出漏洞（文件中保存纯文本）
		green := config.Colors(config.ColorGreen)
		green.Printf("[%s] %s payload: %s=%s\n", sm.config.Method, testURL, param, payload.Value)
		if sm.outputFile != nil {
			vulnOutput := fmt.Sprintf("[%s] %s payload: %s=%s\n", sm.config.Method, testURL, param, payload.Value)
			sm.outputFile.WriteString(vulnOutput)
		}

		// 增加漏洞计数
		sm.vulnCountMux.Lock()
		sm.vulnCount++
		sm.vulnCountMux.Unlock()
	}
	sm.outputMux.Unlock()
}

// scanWithCustomDict 使用自定义字典扫描
func (sm *ScanManager) scanWithCustomDict(params map[string]string) {
	var wg sync.WaitGroup

	// 从文件加载payload
	customPayloads, err := sm.loadCustomPayloads()
	if err != nil {
		red := config.Colors(config.ColorRed)
		red.Printf("[!] 加载字典文件失败: %v\n", err)
		return
	}

	semaphore := make(chan struct{}, sm.config.Threads)

	for paramName := range params {
		for _, payload := range customPayloads {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(param string, pl payloads.Payload) {
				defer func() {
					<-semaphore
					wg.Done()
				}()

				sm.testPayload(param, pl)
			}(paramName, payload)
		}
	}

	wg.Wait()
}

// loadCustomPayloads 从文件加载自定义payload
func (sm *ScanManager) loadCustomPayloads() ([]payloads.Payload, error) {
	file, err := os.Open(sm.config.PayloadFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []payloads.Payload
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 创建payload
		payload := payloads.Payload{
			Value:       line,
			Type:        "自定义字典",
			Description: fmt.Sprintf("字典行 %d: %s", lineNum, line),
			Severity:    "medium",
			Keywords:    []string{},
		}
		result = append(result, payload)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
