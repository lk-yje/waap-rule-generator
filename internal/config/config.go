package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 应用配置结构
type Config struct {
	API     APIConfig     `yaml:"api"`
	Generator GeneratorConfig `yaml:"generator"`
	Validator ValidatorConfig `yaml:"validator"`
	Output    OutputConfig    `yaml:"output"`
}

// APIConfig API 配置
type APIConfig struct {
	Key    string `yaml:"key"`
	Model  string `yaml:"model"`
	URL    string `yaml:"url"`
	Timeout int    `yaml:"timeout"`
}

// GeneratorConfig 规则生成配置
type GeneratorConfig struct {
	MaxTokens   int     `yaml:"max_tokens"`
	Temperature float64 `yaml:"temperature"`
	BatchSize   int     `yaml:"batch_size"`
}

// ValidatorConfig 规则验证配置
type ValidatorConfig struct {
	TestSamples    int    `yaml:"test_samples"`
	Concurrency    int    `yaml:"concurrency"`
	ReportPath     string `yaml:"report_path"`
	MaxExecutionTime int  `yaml:"max_execution_time"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	Format  string `yaml:"format"`
	Path    string `yaml:"path"`
	Prefix  string `yaml:"prefix"`
	Overwrite bool  `yaml:"overwrite"`
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		API: APIConfig{
			Key:    os.Getenv("ZHIPU_API_KEY"),
			Model:  "GLM-5",
			URL:    "https://api.edgefn.net/v1/chat/completions",
			Timeout: 60,
		},
		Generator: GeneratorConfig{
			MaxTokens:   1024,
			Temperature: 0.3,
			BatchSize:   10,
		},
		Validator: ValidatorConfig{
			TestSamples:    100,
			Concurrency:    10,
			ReportPath:     "reports",
			MaxExecutionTime: 5,
		},
		Output: OutputConfig{
			Format:  "regex",
			Path:    "rules",
			Prefix:  "waap_",
			Overwrite: false,
		},
	}
}

// Load 从文件加载配置
func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	if configPath == "" {
		configPath = filepath.Join("config", "config.yaml")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 配置文件不存在，使用默认配置
			return config, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// 环境变量覆盖配置
	if apiKey := os.Getenv("ZHIPU_API_KEY"); apiKey != "" {
		config.API.Key = apiKey
	}

	return config, nil
}

// Save 保存配置到文件
func (c *Config) Save(configPath string) error {
	if configPath == "" {
		configPath = filepath.Join("config", "config.yaml")
	}

	// 确保配置目录存在
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}
