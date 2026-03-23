package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var ruleCache *RuleCache

func init() {
	cacheFile := "./rule_cache.json"
	ruleCache = NewRuleCache(cacheFile)
	categories := ruleCache.GetCategories()
	fmt.Printf("Rule cache initialized with %d entries\n", ruleCache.Size())
	if len(categories) > 0 {
		fmt.Println("Cache categories:")
		for _, category := range categories {
			rules := ruleCache.GetAllByCategory(category)
			fmt.Printf("  - %s: %d rules\n", category, len(rules))
		}
	}
}

const (
	APIURL    = "https://api.edgefn.net/v1/chat/completions"
	ModelName = "GLM-5"
	MaxTokens = 1024
	Timeout   = 180 * time.Second
	MaxRetries = 5
	RetryDelay = 5 * time.Second
)

type Config struct {
	APIKey      string
	Model       string
	APIURL      string
	MaxTokens   int
	Temperature float64
	Timeout     time.Duration
	MaxRetries  int
	RetryDelay  time.Duration
}

type ZhipuRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

type Message struct {
	Role             string `json:"role"`
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content"`
}

type LLMResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Choices []struct {
		Index        int     `json:"index"`
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		APIKey:      os.Getenv("ZHIPU_API_KEY"),
		Model:       ModelName,
		APIURL:      APIURL,
		MaxTokens:   MaxTokens,
		Temperature: 0.3,
		Timeout:     Timeout,
		MaxRetries:  MaxRetries,
		RetryDelay:  RetryDelay,
	}
}

// GenerateRuleByLLM generates regex rule from attack sample
func detectAttackCategory(input string) string {
	input = strings.ToLower(input)
	
	// RCE (Remote Code Execution) patterns
	rcePatterns := []string{
		"eval(", "exec(", "system(", "shell_exec(", "passthru(", "pcntl_exec(",
		"`", "${@exec(", "assert(", "create_function(",
	}
	
	// XSS (Cross-Site Scripting) patterns
	xssPatterns := []string{
		"<script>", "</script>", "alert(", "onload=", "onclick=", "javascript:",
		"<iframe>", "</iframe>", "<img ", "onerror=", "<svg>", "</svg>",
	}
	
	// Command Injection patterns
	cmdPatterns := []string{
		"&&", "||", ";", "|", "`", "\n", "cat /", "ls ", "rm ",
		"mkdir ", "chmod ", "wget ", "curl ",
	}
	
	// Code Injection patterns
	codePatterns := []string{
		"<?php", "?>", "<%", "%>",
	}
	
	// SQL Injection patterns (more specific patterns)
	sqlPatterns := []string{
		"or 1=1", "union select", "select ", "from ", "where ", "insert into",
		"update ", "delete from", "drop table", "--", ";", "#",
	}
	
	// Check RCE first
	for _, pattern := range rcePatterns {
		if strings.Contains(input, pattern) {
			return "RCE"
		}
	}
	
	// Check XSS
	for _, pattern := range xssPatterns {
		if strings.Contains(input, pattern) {
			return "XSS"
		}
	}
	
	// Check Command Injection
	for _, pattern := range cmdPatterns {
		if strings.Contains(input, pattern) {
			return "CMD_INJECT"
		}
	}
	
	// Check Code Injection
	for _, pattern := range codePatterns {
		if strings.Contains(input, pattern) {
			return "CODE_INJECT"
		}
	}
	
	// Check SQL Injection (last, more specific)
	for _, pattern := range sqlPatterns {
		if strings.Contains(input, pattern) {
			return "SQL"
		}
	}
	
	// Check for SQL-like patterns with quotes
	if strings.Contains(input, "'") || strings.Contains(input, "\"") {
		if strings.Contains(input, "or ") || strings.Contains(input, "and ") {
			return "SQL"
		}
	}
	
	return "OTHER"
}

func GenerateRuleByLLM(input string) (string, error) {
	category := detectAttackCategory(input)
	
	// Check cache first
	if rule, exists := ruleCache.Get(category, input); exists {
		fmt.Printf("Cache hit for %s input: %s\n", category, input)
		return rule, nil
	}
	
	// Call API if not in cache
	rule, err := GenerateRuleByLLMWithConfig(input, DefaultConfig())
	if err == nil {
		ruleCache.Set(category, input, rule)
		fmt.Printf("Cache miss, saved %s rule for input: %s\n", category, input)
	}
	return rule, err
}

// GenerateRuleByLLMWithConfig generates regex rule with custom configuration
func GenerateRuleByLLMWithConfig(input string, cfg *Config) (string, error) {
	if cfg.APIKey == "" {
		return "", errors.New("API key is not set")
	}

	prompt := buildPrompt(input)

	reqBody := ZhipuRequest{
		Model: cfg.Model,
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a Web security expert specializing in analyzing attack samples and generating regex rules. Only return the regex pattern, no explanations.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   cfg.MaxTokens,
		Temperature: cfg.Temperature,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	var lastErr error
	for attempt := 0; attempt < cfg.MaxRetries; attempt++ {
		req, err := http.NewRequest("POST", cfg.APIURL, bytes.NewBuffer(jsonData))
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to send request: %w", err)
			time.Sleep(cfg.RetryDelay)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			time.Sleep(cfg.RetryDelay)
			continue
		}

		var llmResp LLMResponse
		if err := json.Unmarshal(body, &llmResp); err != nil {
			lastErr = fmt.Errorf("failed to unmarshal response: %w", err)
			time.Sleep(cfg.RetryDelay)
			continue
		}

		if llmResp.Error.Code != "" {
			lastErr = fmt.Errorf("API error: code=%s, message=%s", llmResp.Error.Code, llmResp.Error.Message)
			time.Sleep(cfg.RetryDelay)
			continue
		}

		if len(llmResp.Choices) == 0 {
			lastErr = errors.New("no response choices returned from API")
			time.Sleep(cfg.RetryDelay)
			continue
		}

		message := llmResp.Choices[0].Message
		content := strings.TrimSpace(message.Content)
		if content == "" {
			content = strings.TrimSpace(message.ReasoningContent)
		}
		rule := extractRegex(content)

		return rule, nil
	}

	return "", fmt.Errorf("failed after %d attempts: %w", cfg.MaxRetries, lastErr)
}

func buildPrompt(input string) string {
	return fmt.Sprintf(`Give me ONE complete regex to detect: %s

Just output the regex, nothing else. Example: (?i)or\s+1\s*=\s*1`, input)
}

func extractRegex(content string) string {
	content = strings.TrimSpace(content)

	// Remove common prefixes
	content = strings.TrimPrefix(content, "Here is the regex pattern:")
	content = strings.TrimPrefix(content, "Regex pattern:")
	content = strings.TrimPrefix(content, "Pattern:")
	content = strings.TrimPrefix(content, "Rule:")
	content = strings.TrimPrefix(content, "Output:")
	content = strings.TrimPrefix(content, "Now:")
	content = strings.TrimPrefix(content, "Here:")
	content = strings.TrimSpace(content)

	// Remove markdown code blocks
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimPrefix(content, "regex")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// Try to extract from backticks first
	parts := strings.Split(content, "`")
	for j := 1; j < len(parts); j += 2 {
		pattern := strings.TrimSpace(parts[j])
		if isRegexPattern(pattern) && len(pattern) > 3 {
			return pattern
		}
	}

	// Take the first line
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "```")
		line = strings.TrimSuffix(line, "```")
		line = strings.TrimSpace(line)
		if isRegexPattern(line) && len(line) > 3 {
			return line
		}
	}

	// Return first non-empty line
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 3 {
			return line
		}
	}

	return content
}

func isRegexPattern(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Check for common regex indicators
	return strings.Contains(s, "(?") || 
		strings.Contains(s, "\\") || 
		strings.Contains(s, "^") || 
		strings.Contains(s, "$") ||
		strings.Contains(s, "*") ||
		strings.Contains(s, "+") ||
		strings.Contains(s, "[") ||
		strings.Contains(s, "(")
}
