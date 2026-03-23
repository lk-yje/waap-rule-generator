package validator

import (
	"fmt"
	"regexp"
	"time"
	"waap-rule-generator/internal/config"
	"waap-rule-generator/internal/scanner"
)

// ValidationResult 验证结果
type ValidationResult struct {
	Valid       bool              `json:"valid"`
	SyntaxValid bool              `json:"syntax_valid"`
	MatchRate   float64           `json:"match_rate"`
	FalseRate   float64           `json:"false_rate"`
	Performance time.Duration     `json:"performance"`
	Complexity  int               `json:"complexity"`
	Errors      []string          `json:"errors"`
	Details     map[string]bool   `json:"details"`
}

// Validator 规则验证器
type Validator struct {
	config *config.Config
}

// NewValidator 创建规则验证器
func NewValidator(cfg *config.Config) *Validator {
	return &Validator{
		config: cfg,
	}
}

// Validate 验证规则
func (v *Validator) Validate(pattern string, positiveSamples []string, negativeSamples []string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Errors:    []string{},
		Details:   make(map[string]bool),
	}

	// 1. 语法验证
	if !v.validateSyntax(pattern, result) {
		result.Valid = false
		return result
	}

	// 2. 规则复杂度评估
	result.Complexity = v.evaluateComplexity(pattern)

	// 3. 匹配测试
	if len(positiveSamples) > 0 {
		v.validateMatching(pattern, positiveSamples, result)
	}

	// 4. 误报测试
	if len(negativeSamples) > 0 {
		v.validateFalsePositive(pattern, negativeSamples, result)
	}

	// 5. 性能测试
	v.validatePerformance(pattern, result)

	// 综合评估
	if result.MatchRate < 0.8 || result.FalseRate > 0.2 {
		result.Valid = false
	}

	return result
}

// validateSyntax 验证语法
func (v *Validator) validateSyntax(pattern string, result *ValidationResult) bool {
	_, err := regexp.Compile(pattern)
	if err != nil {
		result.SyntaxValid = false
		result.Errors = append(result.Errors, "Invalid regex syntax: "+err.Error())
		return false
	}

	result.SyntaxValid = true
	result.Details["syntax"] = true
	return true
}

// validateMatching 验证匹配能力
func (v *Validator) validateMatching(pattern string, samples []string, result *ValidationResult) {
	re, _ := regexp.Compile(pattern)
	matches := 0

	for _, sample := range samples {
		if re.MatchString(sample) {
			matches++
			result.Details["match_"+sample] = true
		} else {
			result.Details["match_"+sample] = false
		}
	}

	result.MatchRate = float64(matches) / float64(len(samples))
	if result.MatchRate < 0.8 {
		result.Errors = append(result.Errors, fmt.Sprintf("Low match rate: %.2f", result.MatchRate))
	}
}

// validateFalsePositive 验证误报率
func (v *Validator) validateFalsePositive(pattern string, samples []string, result *ValidationResult) {
	re, _ := regexp.Compile(pattern)
	falsePositives := 0

	for _, sample := range samples {
		if re.MatchString(sample) {
			falsePositives++
			result.Details["false_"+sample] = true
		} else {
			result.Details["false_"+sample] = false
		}
	}

	result.FalseRate = float64(falsePositives) / float64(len(samples))
	if result.FalseRate > 0.2 {
		result.Errors = append(result.Errors, fmt.Sprintf("High false positive rate: %.2f", result.FalseRate))
	}
}

// validatePerformance 验证性能
func (v *Validator) validatePerformance(pattern string, result *ValidationResult) {
	re, _ := regexp.Compile(pattern)
	
	// 准备测试数据
	testInputs := []string{
		"test input with normal data",
		"user=test&id=123&page=1",
		"<div>normal content</div>",
		"select * from users where id=1",
		"eval('normal function')",
	}
	
	start := time.Now()
	
	// 测试性能
	for i := 0; i < 1000; i++ {
		for _, input := range testInputs {
			re.MatchString(input)
		}
	}

	result.Performance = time.Since(start)
	maxTime := time.Duration(v.config.Validator.MaxExecutionTime) * time.Millisecond
	if result.Performance > maxTime {
		result.Errors = append(result.Errors, "Poor performance: "+result.Performance.String())
	}

	result.Details["performance"] = result.Performance < maxTime
}

// evaluateComplexity 评估规则复杂度
func (v *Validator) evaluateComplexity(pattern string) int {
	complexity := 0
	
	// 计算特殊字符数量
	specialChars := []rune{'*', '+', '?', '|', '(', ')', '[', ']', '{', '}', '^', '$', '\\'}
	for _, char := range pattern {
		for _, special := range specialChars {
			if char == special {
				complexity++
				break
			}
		}
	}
	
	// 计算长度
	if len(pattern) > 50 {
		complexity += 5
	} else if len(pattern) > 20 {
		complexity += 2
	}
	
	return complexity
}

// GenerateTestSamples 生成测试样本
func (v *Validator) GenerateTestSamples(attackType scanner.AttackType, count int) ([]string, []string) {
	positiveSamples := []string{}
	negativeSamples := []string{}

	// 基于攻击类型生成测试样本
	switch attackType {
	case scanner.SQLi:
		positiveSamples = []string{
			"' OR 1=1 --",
			"' OR '1'='1",
			"union select 1,2,3",
			"select * from users where id=1",
			"' AND 1=1 #",
			"1' OR '1'='1' --",
			"' OR 1=1/*",
			"1 OR 1=1",
			"' OR 'a'='a",
			"' OR 1=1 -- -",
		}
		negativeSamples = []string{
			"user=test",
			"id=123",
			"search=query",
			"page=1",
			"name=John Doe",
			"email=test@example.com",
			"password=secret123",
			"sort=asc",
			"filter=active",
			"limit=10",
		}
	case scanner.XSS:
		positiveSamples = []string{
			"<script>alert('XSS')</script>",
			"javascript:alert('XSS')",
			"<img src='x' onerror='alert(1)'>",
			"<iframe src='javascript:alert(1)'></iframe>",
			"<svg onload='alert(1)'>",
			"<body onload='alert(1)'>",
			"<div onclick='alert(1)'>click</div>",
			"<a href='javascript:alert(1)'>link</a>",
			"<input type='text' onfocus='alert(1)'>",
			"<textarea onblur='alert(1)'>test</textarea>",
		}
		negativeSamples = []string{
			"<div>test</div>",
			"<p>hello</p>",
			"<a href='test'>link</a>",
			"<img src='image.jpg'>",
			"<h1>title</h1>",
			"<ul><li>item</li></ul>",
			"<form action='submit.php'>",
			"<input type='text' name='username'>",
			"<button type='submit'>Submit</button>",
			"<footer>copyright</footer>",
		}
	case scanner.RCE:
		positiveSamples = []string{
			"eval('alert(1)')",
			"exec('ls')",
			"system('whoami')",
			"shell_exec('pwd')",
			"passthru('ls -la')",
			"pcntl_exec('/bin/bash')",
			"`ls`",
			"${@exec('ls')}",
			"eval($_POST['cmd'])",
			"assert('exec(\\"ls\\")')",
		}
		negativeSamples = []string{
			"execute('test')",
			"run('command')",
			"call('function')",
			"process('data')",
			"handle('input')",
			"compute('value')",
			"calculate('sum')",
			"processRequest('data')",
			"handleEvent('click')",
			"executeFunction('test')",
		}
	case scanner.CommandInjection:
		positiveSamples = []string{
			"cat /etc/passwd",
			"ls -la",
			"whoami",
			"pwd",
			"echo 'test'",
			"rm -rf /",
			"mkdir test",
			"cp file1 file2",
			"mv file1 file2",
			"chmod 777 file",
		}
		negativeSamples = []string{
			"file=document.txt",
			"path=/home/user",
			"name=test.txt",
			"directory=images",
			"filename=report.pdf",
			"folder=documents",
			"location=/var/www",
			"destination=/tmp",
			"source=/src",
			"target=/dist",
		}
	case scanner.LFI:
		positiveSamples = []string{
			"../../etc/passwd",
			"../..//etc/passwd",
			"../../windows/win.ini",
			"../etc/passwd",
			"..\\..\\windows\\win.ini",
			"../../../etc/passwd",
			"/etc/passwd",
			"c:/windows/win.ini",
			"file:///etc/passwd",
			"http://localhost/etc/passwd",
		}
		negativeSamples = []string{
			"file=document.txt",
			"path=images/photo.jpg",
			"name=test.pdf",
			"page=home",
			"template=header",
			"view=profile",
			"include=footer",
			"file=report.txt",
			"image=logo.png",
			"script=main.js",
		}
	case scanner.SSRF:
		positiveSamples = []string{
			"http://localhost",
			"https://127.0.0.1",
			"file:///etc/passwd",
			"gopher://127.0.0.1:25/_HELO",
			"dict://127.0.0.1:6379/info",
			"ftp://127.0.0.1:21",
			"http://[::1]",
			"http://0.0.0.0",
			"http://127.1",
			"http://localhost:8080",
		}
		negativeSamples = []string{
			"https://example.com",
			"http://google.com",
			"https://github.com",
			"http://api.example.com",
			"https://api.github.com",
			"http://cdn.example.com",
			"https://cdn.cloudflare.com",
			"http://static.example.com",
			"https://fonts.googleapis.com",
			"http://cdnjs.cloudflare.com",
		}
	case scanner.SensitiveInfo:
		positiveSamples = []string{
			"password=secret123",
			"api_key=sk-123456",
			"token=abcdef123456",
			"secret=mysecret",
			"auth=bearer 12345",
			"private_key=-----BEGIN PRIVATE KEY-----",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC",
			"password_hash=$2y$10$",
			"database_url=mysql://user:pass@localhost/db",
			"connection_string=Server=localhost;Database=test;User Id=sa;Password=secret;",
		}
		negativeSamples = []string{
			"user=test",
			"name=John Doe",
			"email=test@example.com",
			"address=123 Main St",
			"phone=555-1234",
			"city=New York",
			"state=NY",
			"zip=10001",
			"country=USA",
			"age=30",
		}
	default:
		positiveSamples = []string{"test attack"}
		negativeSamples = []string{"test normal"}
	}

	// 限制样本数量
	if len(positiveSamples) > count {
		positiveSamples = positiveSamples[:count]
	}
	if len(negativeSamples) > count {
		negativeSamples = negativeSamples[:count]
	}

	return positiveSamples, negativeSamples
}
