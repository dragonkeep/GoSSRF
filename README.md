# GoSSRF - SSRF漏洞检测工具

<div align="center">


一款高效、灵活的 SSRF（Server-Side Request Forgery）漏洞检测工具

[![Go Version](https://img.shields.io/badge/Go-1.20+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache-green.svg)](LICENSE)

</div>

## ✨ 特性

- 🎯 **多种扫描模式**
  - 内网端口扫描（优先探测高危端口）
  - 文件读取测试（支持file://、dict://、gopher://等协议）
  - 云服务元数据接口探测（AWS/GCP/阿里云）
  - OOB（Out-of-Band）带外数据检测

- 🚀 **高性能并发**
  - 支持自定义并发线程数
  - 智能互斥锁保护输出顺序
  - 高效的payload管理

- 🎨 **友好的输出**
  - 彩色命令行输出（漏洞绿色，错误红色）
  - 输出文件与命令行内容完全一致
  - 简洁清晰的扫描进度

- 🔧 **灵活配置**
  - 支持自定义HTTP方法（GET/POST/PUT等）
  - 支持自定义HTTP Headers（Burp格式）
  - 支持自定义Payload字典
  - 支持CIDR网段扫描

## 📦 安装

### 方式一：下载预编译版本

从 [Releases](https://github.com/yourusername/GoSSRF/releases) 下载最新版本

### 方式二：从源码编译

```bash
git clone https://github.com/yourusername/GoSSRF.git
cd GoSSRF/GoSSRFClient
go build -o GoSSRF.exe
```

## 📋 命令行参数

```
参数说明：
  -u string
        目标URL（必需）
  -p string
        要测试的参数名（必需）
  -X string
        HTTP请求方法 (default "GET")
  -w string
        自定义payload字典文件（指定后跳过默认扫描）
  -H string
        自定义HTTP Headers文件 (default "Header.txt")
  -i string
        内网扫描目标（支持: CIDR 192.168.1.0/24 | 单IP 192.168.1.1 | 范围 192.168.1.1-10|域名 localhost）
  -ports string
        扫描端口范围（例如：1-1000 或 80,443,3306，不指定则扫描默认高危端口）
  -oob string
        OOB服务器地址（指定后自动启用OOB测试）
  -t int
        并发线程数 (default 10)
  -timeout int
        HTTP请求超时时间（秒） (default 10)
  -delaytime int 
        延迟请求时间（秒）（default 0）
  -all 
        指定后扫描所有内置的字典
  -o string
        结果输出文件（内容与命令行输出一致）
```

## 📂 项目结构

```
GoSSRF/
├── main.go              # 程序入口
├── config/              # 配置模块
│   ├── config.go        # 配置解析和管理
│   ├── color.go         # 颜色输出定义
│   └── logo.go          # Logo显示
├── detector/            # 检测模块
│   └── detector.go      # SSRF检测逻辑
├── scanner/             # 扫描模块
│   ├── scan_manager.go  # 扫描管理器
│   └── url_builder.go   # URL构造器
├── payloads/            # Payload模块
│   └── payloads.go      # 内置payload定义
├── dict/                # 内置字典目录
│   ├── bypass_techniques.txt
│   ├── cloud_metadata.txt
│   ├── file_read.txt
│   ├── high_risk_ports.txt
│   ├── internal_ip.txt
│   └── protocol_bypass.txt
├── Header.txt           # 默认HTTP Headers配置
└── README.md            # 本文档
```

## 🎯 检测范围

### 默认扫描

#### 1. 高危端口扫描

- **6379** - Redis（未授权访问）
- **3306** - MySQL（数据库）
- **5432** - PostgreSQL（数据库）
- **27017** - MongoDB（NoSQL数据库）
- **9200** - Elasticsearch（搜索引擎）
- **11211** - Memcached（缓存）
- **2375** - Docker API（容器管理）
- **8086** - InfluxDB（时序数据库）
- **5000** - Docker Registry（镜像仓库）

#### 2. 文件协议测试

- `file:///etc/passwd` - Linux用户文件
- `file:///etc/shadow` - Linux密码哈希
- `file:///proc/self/environ` - 进程环境变量
- `file:///c:/windows/win.ini` - Windows配置
- `dict://127.0.0.1:6379/info` - Dict协议
- `gopher://127.0.0.1:6379/_INFO` - Gopher协议

#### 3. 云服务元数据

- **AWS**: `http://169.254.169.254/latest/meta-data/`
- **Google Cloud**: `http://metadata.google.internal/computeMetadata/v1/`
- **阿里云**: `http://100.100.100.200/latest/meta-data/`

## 📊 输出示例

![输出](images/0a87456e-f96b-42f1-9571-d51b123cd387.png)


## 🚀 快速开始

### 基本使用

```bash
# GET请求测试
GoSSRF.exe -u "http://example.com/api" -p url -X GET

# POST请求测试
GoSSRF.exe -u "http://example.com/api" -p data -X POST

# 指定输出文件
GoSSRF.exe -u "http://example.com/api" -p url -o result.txt
```

### 高级用法

#### 1. 使用自定义字典

```bash
# 使用自定义payload字典（会跳过默认扫描）
GoSSRF.exe -u "http://example.com/api" -p url -w custom_payloads.txt
```

字典文件格式：

```
# 这是注释
http://127.0.0.1:6379
http://192.168.1.100:3306
file:///etc/passwd
http://169.254.169.254/latest/meta-data/
```

#### 2. 自定义HTTP Headers

```bash
# 使用自定义Headers
GoSSRF.exe -u "http://example.com/api" -p url -H Header.txt
```

Header.txt文件格式（Burp兼容）：

```
# HTTP Headers - 可以直接从Burp复制粘贴
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Cookie: session=abc123; token=xyz456
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
Accept: application/json
```

#### 3. 内网网段扫描

```bash
# 默认只扫描127.0.0.1
GoSSRF.exe -u "http://example.com/api" -p url

# 扫描指定内网网段
GoSSRF.exe -u "http://example.com/api" -p url -i 192.168.1.0/24

# 扫描多个C段
GoSSRF.exe -u "http://example.com/api" -p url -i 10.0.0.0/16
```

#### 4. 调整并发和超时

```bash
# 使用20个并发线程，超时30秒
GoSSRF.exe -u "http://example.com/api" -p url -t 20 -timeout 30
```


## 📄 许可证

本项目采用 Apache 许可证 - 详见 [LICENSE](LICENSE) 文件

## ⚠️ 免责声明

本工具仅用于授权的安全测试，请勿用于非法用途。使用本工具进行测试前，请确保：

1. 已获得目标系统所有者的明确授权
2. 遵守相关法律法规
3. 承担使用本工具产生的一切后果

