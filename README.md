# WAAP 智能规则生成工具

## 项目简介

WAAP 智能规则生成工具是一个基于 Go 语言和 GLM-5 大模型的 Web 应用防护规则生成系统，能够自动分析攻击样本并生成 WAF/WAAP 防护规则，支持多种攻击类型的检测和防护。

## 主要功能

- **智能规则生成**：利用 GLM-5 大模型生成高质量的防护规则
- **多类型支持**：支持 SQL 注入、XSS、RCE 等多种攻击类型
- **规则验证**：自动验证生成规则的有效性和准确性
- **缓存机制**：本地缓存规则，提高响应速度
- **批量处理**：支持批量分析攻击样本和生成规则

## 项目结构

```
waap-rule-generator/
├── cmd/              # 命令行工具
├── internal/         # 内部包
│   ├── config/       # 配置管理
│   ├── generator/    # 规则生成器
│   ├── validator/    # 规则验证器
│   ├── scanner/      # 攻击类型扫描器
├── pkg/              # 公共包
│   ├── llm/          # LLM API 接口
├── samples/          # 攻击样本
├── go.mod            # Go 模块配置
├── main.go           # 主程序入口
├── README.md         # 项目说明
```

## 环境要求

### 系统要求

- Go 1.26+ 环境
- 有效的 GLM-5 API 密钥

### 依赖安装

```bash
go mod tidy
```

### 设置 API 密钥

通过环境变量设置：

```bash
# Windows PowerShell
$env:ZHIPU_API_KEY = "your-api-key"

# Linux/macOS
export ZHIPU_API_KEY="your-api-key"
```

### 快速开始

```bash
# 运行主程序
go run main.go

# 运行规则测试
go run test_rules.go
```

## 使用方法

### 1. 生成规则

```bash
# 运行主程序生成规则
go run main.go

# 或使用命令行工具
```

### 2. 验证规则

```bash
# 运行规则测试
go run test_rules.go

# 验证生成的规则
```

### 3. 批量处理

```bash
# 批量处理样本目录
waap batch -d samples -o rules
```

## 支持的攻击类型

- **SQL 注入** (sqli)
- **跨站脚本** (xss)
- **远程代码执行** (rce)
- **命令注入** (command_injection)
- **本地文件包含** (lfi)
- **服务器请求伪造** (ssrf)
- **敏感信息泄露** (sensitive_info)

## 技术特点

本项目采用现代化的技术栈：

- **大模型集成**：使用 GLM-5 大模型生成智能规则
- **缓存系统**：本地分类缓存，提高性能
- **并发处理**：支持多线程批量处理

## 配置说明

可通过 `config/config.yaml` 文件自定义配置：

```yaml
api:
  key: "your-api-key"      # API 密钥
  model: "GLM-5"           # 模型名称
  url: "https://api.edgefn.net/v1/chat/completions"  # API 地址
  timeout: 60               # 超时时间

generator:
  max_tokens: 1024          # 最大 token 数
  temperature: 0.3          # 温度参数
  batch_size: 10            # 批量处理大小

validator:
  test_samples: 100         # 测试样本数
  concurrency: 10           # 并发数
  report_path: "reports"    # 报告路径
  max_execution_time: 5     # 最大执行时间

output:
  format: "regex"           # 输出格式
  path: "rules"            # 输出路径
  prefix: "waap_"          # 规则前缀
  overwrite: false          # 覆盖模式
```

## 示例

### 规则生成示例

**输入**：
```
user='or 1=1#
```

**输出**：
```
=== Attack Sample: user='or 1=1# ===
Generated Rule: (?i)or\s+1\s*=\s*1
```

### 规则验证示例

```
=== Testing SQLi Rule ===
Rule: (?i)or\s+1\s*=\s*1
PASS: 'user='or 1=1#' -> true (expected: true)
PASS: 'OR 1 = 1' -> true (expected: true)
PASS: 'or1=1' -> false (expected: false)
PASS: 'user=test' -> false (expected: false)
```

## 项目优势

- **智能生成**：利用大模型生成高质量规则，减少人工工作量
- **高效缓存**：本地缓存规则，提高响应速度和系统性能
- **全面验证**：多维度测试确保规则质量和有效性

## 注意事项

1. **API 费用**：使用 GLM-5 API 会产生相应的费用，请合理使用
2. **规则质量**：生成的规则需要根据实际情况进行调整和优化
3. **性能考虑**：复杂规则可能影响 WAF 性能，请适度使用
4. **误报处理**：规则可能产生误报，需要根据实际场景调整

## 待办事项

- [ ] 增加更多攻击类型支持
- [ ] 支持导出 WAF 规则格式
- [ ] 增加 Web 界面
- [ ] 增加规则管理功能
- [ ] 增加性能测试工具

## 贡献

欢迎提交 Issue 和 Pull Request 来改进本项目

## 许可证

MIT License
