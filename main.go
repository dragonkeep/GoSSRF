package main

import (
	"flag"
	"fmt"
	"os"

	"gosssrf-client/config"
	"gosssrf-client/detector"
	"gosssrf-client/scanner"
)

func printBanner() {
	config.Logo()
}

func main() {
	// 解析命令行参数
	cfg := config.ParseFlags()
	flag.Parse()

	printBanner()

	// 验证配置
	if err := cfg.Validate(); err != nil {
		red := config.Colors(config.ColorRed)
		red.Printf("[!] 配置错误: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// 打印配置信息
	cfg.Print()

	// 初始化检测器
	det := detector.NewDetector(cfg)

	// 如果指定了输出文件，创建输出文件
	var outputFile *os.File
	if cfg.OutputFile != "" {
		var err error
		outputFile, err = os.Create(cfg.OutputFile)
		if err != nil {
			red := config.Colors(config.ColorRed)
			red.Printf("创建输出文件失败: %v\n", err)
			os.Exit(1)
		}
		defer outputFile.Close()
	}

	// 初始化扫描器（传入输出文件）
	scanManager := scanner.NewScanManager(cfg, det, outputFile)

	// 执行扫描
	fmt.Println()
	if outputFile != nil {
		outputFile.WriteString("\n")
	}

	vulnerableCount := scanManager.RunScan()

	// 打印摘要
	summaryMsg := fmt.Sprintf("\n扫描完成，存在 %d 个SSRF测试点\n", vulnerableCount)
	fmt.Print(summaryMsg)

	if outputFile != nil {
		outputFile.WriteString(summaryMsg)
	}
}
