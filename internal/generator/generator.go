package generator

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"waap-rule-generator/internal/config"
	"waap-rule-generator/internal/scanner"
	"waap-rule-generator/pkg/llm"
)

// Rule ?????
type Rule struct {
	Type        scanner.AttackType `json:"type"`
	Pattern     string            `json:"pattern"`
	Keywords    []string          `json:"keywords"`
	Description string            `json:"description"`
	Confidence  float64           `json:"confidence"`
	Source      string            `json:"source"`
	GeneratedAt time.Time         `json:"generated_at"`
	Complexity  int               `json:"complexity"`
}

// Generator ??????????
type Generator struct {
	config     *config.Config
	ruleCache  map[string]Rule
	cacheMutex sync.RWMutex
}

// NewGenerator ??????????????
func NewGenerator(cfg *config.Config) *Generator {
	return &Generator{
		config:    cfg,
		ruleCache: make(map[string]Rule),
	}
}

// Generate ???????
func (g *Generator) Generate(input string) (*Rule, error) {
	// ??üv??
	g.cacheMutex.RLock()
	if rule, exists := g.ruleCache[input]; exists {
		g.cacheMutex.RUnlock()
		return &rule, nil
	}
	g.cacheMutex.RUnlock()

	// ????????
	scanResults := scanner.Scan(input)
	highestResult := scanner.GetHighestConfidence(scanResults)

	// ???????
	pattern, err := g.generatePattern(input, highestResult.Type)
	if err != nil {
		return nil, err
	}

	// ????????
	keywords := g.extractKeywords(input, highestResult.Type)

	// ??????????
	complexity := g.calculateComplexity(pattern)

	rule := &Rule{
		Type:        highestResult.Type,
		Pattern:     pattern,
		Keywords:    keywords,
		Description: highestResult.Description,
		Confidence:  highestResult.Confidence,
		Source:      input,
		GeneratedAt: time.Now(),
		Complexity:  complexity,
	}

	// ???????
	g.cacheMutex.Lock()
	g.ruleCache[input] = *rule
	g.cacheMutex.Unlock()

	return rule, nil
}

// GenerateBatch ???????????
func (g *Generator) GenerateBatch(inputs []string) ([]*Rule, error) {
	results := make([]*Rule, len(inputs))
	errors := make([]error, len(inputs))
	var wg sync.WaitGroup

	for i, input := range inputs {
		wg.Add(1)
		go func(idx int, sample string) {
			defer wg.Done()
			rule, err := g.Generate(sample)
			results[idx] = rule
			errors[idx] = err
		}(i, input)
	}

	wg.Wait()

	// ???????§Õ???
	for _, err := range errors {
		if err != nil {
			return results, err
		}
	}

	return results, nil
}

// generatePattern ??????????
func (g *Generator) generatePattern(input string, attackType scanner.AttackType) (string, error) {
	// ????LLM????
	llmConfig := llm.DefaultConfig()
	llmConfig.APIKey = g.config.API.Key
	llmConfig.Model = g.config.API.Model
	llmConfig.Timeout = time.Duration(g.config.API.Timeout) * time.Second

	// ???????????????????
	prompt := g.buildPrompt(input, attackType)

	// ???? LLM ???????
	pattern, err := llm.GenerateRuleByLLMWithConfig(prompt, llmConfig)
	if err != nil {
		return "", err
	}

	return pattern, nil
}

// buildPrompt ?????????
func (g *Generator) buildPrompt(input string, attackType scanner.AttackType) string {
	attackDescription := g.getAttackDescription(attackType)
	specificGuidelines := g.getSpecificGuidelines(attackType)

	return fmt.Sprintf(`Analyze the following %s attack sample and generate a regex pattern to match this type of attack.

Attack sample: %s

%s

Requirements:
1. The regex should match the attack pattern and its variants
2. Consider case-insensitivity, whitespace variations, and common bypass techniques
3. Only return the regex pattern itself, no explanations or markdown formatting
4. The pattern should be precise and minimize false positives
5. Ensure the pattern is efficient and doesn't cause ReDoS vulnerabilities

Example format: (?i)or\s+1\s*=\s*1`, attackDescription, input, specificGuidelines)
}

// getAttackDescription ???????????????
func (g *Generator) getAttackDescription(attackType scanner.AttackType) string {
	switch attackType {
	case scanner.SQLi:
		return "SQL injection"
	case scanner.XSS:
		return "cross-site scripting (XSS)"
	case scanner.RCE:
		return "remote code execution (RCE)"
	case scanner.CommandInjection:
		return "command injection"
	case scanner.CSRF:
		return "cross-site request forgery (CSRF)"
	case scanner.LFI:
		return "local file inclusion (LFI)"
	case scanner.SSRF:
		return "server-side request forgery (SSRF)"
	case scanner.SensitiveInfo:
		return "sensitive information exposure"
	default:
		return "web attack"
	}
}

// getSpecificGuidelines ??????????????????
func (g *Generator) getSpecificGuidelines(attackType scanner.AttackType) string {
	switch attackType {
	case scanner.SQLi:
		return "Specific guidelines:\n- Match common SQL injection patterns like OR 1=1, UNION SELECT, etc.\n- Consider comments (--, #, /* */) and different whitespace variations\n- Account for case variations and encoding bypasses"
	case scanner.XSS:
		return "Specific guidelines:\n- Match script tags, event handlers, and javascript: URLs\n- Consider different tag variations and attribute placements\n- Account for encoding and obfuscation techniques"
	case scanner.RCE:
		return "Specific guidelines:\n- Match code execution functions like eval, exec, system, etc.\n- Consider different function call patterns and argument variations\n- Account for string concatenation and obfuscation"
	case scanner.CommandInjection:
		return "Specific guidelines:\n- Match common shell commands and command separators (;, &&, ||)\n- Consider different command execution contexts\n- Account for whitespace variations and bypass techniques"
	case scanner.LFI:
		return "Specific guidelines:\n- Match path traversal patterns like ../ and ..\\\n- Consider common sensitive files like /etc/passwd\n- Account for different path separator variations"
	case scanner.SSRF:
		return "Specific guidelines:\n- Match local addresses like localhost, 127.0.0.1\n- Match dangerous schemes like file://, gopher://, dict://\n- Consider different IP address formats and bypass techniques"
	case scanner.SensitiveInfo:
		return "Specific guidelines:\n- Match sensitive keywords like password, secret, token\n- Consider common credential patterns and formats\n- Account for different encoding and obfuscation techniques"
	default:
		return ""
	}
}

// extractKeywords ????????
func (g *Generator) extractKeywords(input string, attackType scanner.AttackType) []string {
	// ???????????????????
	keywords := make([]string, 0)

	switch attackType {
	case scanner.SQLi:
		keywords = append(keywords, "or", "and", "union", "select", "from", "where", "drop", "insert", "update", "delete", "--", "#", "/*")
	case scanner.XSS:
		keywords = append(keywords, "script", "javascript", "onerror", "onload", "onclick", "iframe", "img", "link", "object", "embed", "onmouseover", "onfocus", "onblur")
	case scanner.RCE:
		keywords = append(keywords, "eval", "exec", "system", "shell_exec", "passthru", "pcntl_exec", "assert")
	case scanner.CommandInjection:
		keywords = append(keywords, "cat", "ls", "cp", "rm", "mkdir", "chmod", "ping", "whoami", "bash", "sh", ";", "&&", "||")
	case scanner.LFI:
		keywords = append(keywords, "../", "..\\", "etc/passwd", "proc/self/environ", "include", "require", "file://")
	case scanner.SSRF:
		keywords = append(keywords, "localhost", "127.0.0.1", "file://", "gopher://", "dict://", "ftp://", "10.0.0.1", "172.16.", "192.168.")
	case scanner.SensitiveInfo:
		keywords = append(keywords, "password", "secret", "token", "api_key", "auth", "session", "cookie", "private_key", "ssh-rsa", "database_url")
	}

	// ????????????????????
	inputKeywords := g.extractFromInput(input, attackType)
	keywords = append(keywords, inputKeywords...)

	// ???
	keywordMap := make(map[string]bool)
	uniqueKeywords := make([]string, 0)
	for _, keyword := range keywords {
		if !keywordMap[keyword] && len(keyword) > 1 {
			keywordMap[keyword] = true
			uniqueKeywords = append(uniqueKeywords, keyword)
		}
	}

	return uniqueKeywords
}

// extractFromInput ????????????????
func (g *Generator) extractFromInput(input string, attackType scanner.AttackType) []string {
	keywords := make([]string, 0)

	// ??????????
	cleanedInput := regexp.MustCompile(`[^a-zA-Z0-9_\-./]`).ReplaceAllString(input, " ")
	words := strings.Fields(cleanedInput)

	// ????????????
	for _, word := range words {
		word = strings.TrimSpace(word)
		if len(word) > 2 && len(word) < 20 {
			keywords = append(keywords, word)
		}
	}

	// ????????
	switch attackType {
	case scanner.SQLi:
		// ??? SQL ??????????
		sqlPatterns := regexp.MustCompile(`(select|from|where|union|insert|update|delete|drop|create|alter|truncate)`)
		matches := sqlPatterns.FindAllString(input, -1)
		keywords = append(keywords, matches...)
	case scanner.XSS:
		// ??? HTML ????????
		tagPatterns := regexp.MustCompile(`<(\w+)|on(\w+)=`)
		matches := tagPatterns.FindAllString(input, -1)
		keywords = append(keywords, matches...)
	case scanner.CommandInjection:
		// ???????????
		cmdPatterns := regexp.MustCompile(`(cat|ls|rm|mkdir|chmod|ping|whoami|bash|sh)`)
		matches := cmdPatterns.FindAllString(input, -1)
		keywords = append(keywords, matches...)
	}

	return keywords
}

// calculateComplexity ??????????
func (g *Generator) calculateComplexity(pattern string) int {
	complexity := 0
	
	// ???????????????
	specialChars := []rune{'*', '+', '?', '|', '(', ')', '[', ']', '{', '}', '^', '$', '\\'}
	for _, char := range pattern {
		for _, special := range specialChars {
			if char == special {
				complexity++
				break
			}
		}
	}
	
	// ??????
	if len(pattern) > 50 {
		complexity += 5
	} else if len(pattern) > 20 {
		complexity += 2
	}
	
	return complexity
}

// ClearCache ??????
func (g *Generator) ClearCache() {
	g.cacheMutex.Lock()
	defer g.cacheMutex.Unlock()
	g.ruleCache = make(map[string]Rule)
}

// CacheSize ????????§³
func (g *Generator) CacheSize() int {
	g.cacheMutex.RLock()
	defer g.cacheMutex.RUnlock()
	return len(g.ruleCache)
}
