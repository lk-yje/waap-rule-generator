package scanner

import (
	"regexp"
	"strings"
)

// AttackType 攻击类型
type AttackType string

const (
	SQLi            AttackType = "sqli"            // SQL 注入
	XSS             AttackType = "xss"             // 跨站脚本
	RCE             AttackType = "rce"             // 远程代码执行
	CommandInjection AttackType = "command_injection" // 命令注入
	CSRF            AttackType = "csrf"            // 跨站请求伪造
	LFI             AttackType = "lfi"             // 本地文件包含
	SSRF            AttackType = "ssrf"            // 服务器端请求伪造
	SensitiveInfo   AttackType = "sensitive_info"   // 敏感信息泄露
	Unknown         AttackType = "unknown"         // 未知攻击类型
)

// AttackPattern 攻击模式
type AttackPattern struct {
	Type        AttackType
	Patterns    []string
	Description string
}

// 攻击模式定义
var attackPatterns = []AttackPattern{
	{
		Type: SQLi,
		Patterns: []string{
			"'\\s*or\\s*1\\s*=\\s*1",
			"union\\s+select",
			"drop\\s+table",
			"insert\\s+into",
			"update\\s+.*set",
			"delete\\s+from",
			"information_schema",
			"select\\s+.*from",
			"\\bor\\b",
			"\\band\\b",
			"\\bxor\\b",
			"--",
			"#",
			"\\bwhere\\b",
		},
		Description: "SQL Injection",
	},
	{
		Type: XSS,
		Patterns: []string{
			"<script",
			"javascript:",
			"onerror=",
			"onload=",
			"onclick=",
			"<iframe",
			"<img.*src=",
			"<link.*href=",
			"<object",
			"<embed",
			"<svg",
			"<form",
			"<input",
			"<textarea",
			"<body.*on",
		},
		Description: "Cross-Site Scripting",
	},
	{
		Type: RCE,
		Patterns: []string{
			"eval\\s*\\(",
			"exec\\s*\\(",
			"system\\s*\\(",
			"shell_exec\\s*\\(",
			"passthru\\s*\\(",
			"`.*`",
			"\\bexec\\b",
			"\\bsystem\\b",
			"\\beval\\b",
			"\\bexecve\\b",
			"\\bfork\\b",
			"\\bspawn\\b",
		},
		Description: "Remote Code Execution",
	},
	{
		Type: CommandInjection,
		Patterns: []string{
			"\\|\\s*",
			";\\s*",
			"&&\\s*",
			"\\bcat\\b",
			"\\bls\\b",
			"\\bcp\\b",
			"\\brm\\b",
			"\\bmkdir\\b",
			"\\brmdir\\b",
			"\\bchmod\\b",
			"\\bchown\\b",
			"\\bping\\b",
			"\\bwhoami\\b",
			"\\bid\\b",
			"\\buname\\b",
			"\\bhostname\\b",
		},
		Description: "Command Injection",
	},
	{
		Type: LFI,
		Patterns: []string{
			"../",
			"..\\\\",
			"/etc/passwd",
			"/etc/shadow",
			"/proc/self/environ",
			"/proc/version",
			"/boot.ini",
			"windows\\\\system32",
			"win.ini",
			"\\binclude\\b",
			"\\brequire\\b",
		},
		Description: "Local File Inclusion",
	},
	{
		Type: SSRF,
		Patterns: []string{
			"http://localhost",
			"http://127.0.0.1",
			"http://0.0.0.0",
			"file://",
			"gopher://",
			"dict://",
			"sftp://",
			"ldap://",
			"telnet://",
			"ftp://",
		},
		Description: "Server-Side Request Forgery",
	},
	{
		Type: SensitiveInfo,
		Patterns: []string{
			"password=",
			"pass=",
			"pwd=",
			"secret=",
			"token=",
			"api_key=",
			"apikey=",
			"auth=",
			"session=",
			"cookie=",
			"Authorization:",
			"Bearer ",
			"Basic ",
			"AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY",
		},
		Description: "Sensitive Information Exposure",
	},
}

// ScanResult 扫描结果
type ScanResult struct {
	Type        AttackType
	Confidence  float64
	Patterns    []string
	Description string
}

// Scan 扫描攻击类型
func Scan(input string) []ScanResult {
	input = strings.ToLower(input)
	results := make([]ScanResult, 0)

	for _, pattern := range attackPatterns {
		matches := 0
		totalPatterns := len(pattern.Patterns)

		for _, p := range pattern.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			if re.MatchString(input) {
				matches++
			}
		}

		if matches > 0 {
			confidence := float64(matches) / float64(totalPatterns)
			results = append(results, ScanResult{
				Type:        pattern.Type,
				Confidence:  confidence,
				Patterns:    pattern.Patterns,
				Description: pattern.Description,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, ScanResult{
			Type:        Unknown,
			Confidence:  1.0,
			Patterns:    []string{},
			Description: "Unknown Attack Type",
		})
	}

	return results
}

// GetHighestConfidence 获取置信度最高的攻击类型
func GetHighestConfidence(results []ScanResult) ScanResult {
	if len(results) == 0 {
		return ScanResult{
			Type:        Unknown,
			Confidence:  1.0,
			Patterns:    []string{},
			Description: "Unknown Attack Type",
		}
	}

	highest := results[0]
	for _, result := range results {
		if result.Confidence > highest.Confidence {
			highest = result
		}
	}

	return highest
}
