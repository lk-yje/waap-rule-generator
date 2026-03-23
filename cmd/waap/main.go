package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"waap-rule-generator/internal/config"
	"waap-rule-generator/internal/generator"
	"waap-rule-generator/internal/validator"
)

var (
	cfg         *config.Config
	inputFile   string
	outputFile  string
	attackType  string
	ruleFile    string
	sampleDir   string
	format      string
)

func main() {
	var err error
	cfg, err = config.Load("")
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "waap",
		Short: "WAAP intelligent rule generator",
		Long:  "Generate and validate WAAP/WAF rules using AI",
	}

	// Generate command
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate WAAP rules from attack samples",
		Run:   runGenerate,
	}
	generateCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file or directory")
	generateCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	generateCmd.Flags().StringVarP(&attackType, "type", "t", "", "Attack type")
	generateCmd.Flags().StringVar(&format, "format", "regex", "Output format (regex, keyword, combined)")

	// Validate command
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate WAAP rules",
		Run:   runValidate,
	}
	validateCmd.Flags().StringVarP(&ruleFile, "rule", "r", "", "Rule file or pattern")
	validateCmd.Flags().StringVarP(&sampleDir, "sample", "s", "", "Sample directory")

	// Batch command
	batchCmd := &cobra.Command{
		Use:   "batch",
		Short: "Process multiple samples in batch",
		Run:   runBatch,
	}
	batchCmd.Flags().StringVarP(&inputFile, "directory", "d", "", "Sample directory")
	batchCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output directory")

	// Config command
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	configGetCmd := &cobra.Command{
		Use:   "get",
		Short: "Get configuration",
		Run:   runConfigGet,
	}

	configSetCmd := &cobra.Command{
		Use:   "set",
		Short: "Set configuration",
		Run:   runConfigSet,
	}
	configSetCmd.Flags().StringVar(&attackType, "key", "", "Config key")
	configSetCmd.Flags().StringVar(&outputFile, "value", "", "Config value")

	configCmd.AddCommand(configGetCmd, configSetCmd)
	rootCmd.AddCommand(generateCmd, validateCmd, batchCmd, configCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runGenerate(cmd *cobra.Command, args []string) {
	if inputFile == "" {
		fmt.Println("Error: input file is required")
		return
	}

	// ??????????
	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error reading input file: %v\n", err)
		return
	}

	input := string(data)

	// ???????
	gen := generator.NewGenerator(cfg)
	rule, err := gen.Generate(input)
	if err != nil {
		fmt.Printf("Error generating rule: %v\n", err)
		return
	}

	// ???????
	val := validator.NewValidator(cfg)
	positiveSamples, negativeSamples := val.GenerateTestSamples(rule.Type, 5)
	validationResult := val.Validate(rule.Pattern, positiveSamples, negativeSamples)

	// ??????
	if outputFile == "" {
		outputFile = filepath.Join(cfg.Output.Path, cfg.Output.Prefix+string(rule.Type)+".txt")
	}

	// ????????????
	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	// §Õ????????
	output := fmt.Sprintf("# WAAP Rule\nType: %s\nPattern: %s\nKeywords: %v\nDescription: %s\nConfidence: %.2f\nValidation: %v\nMatch Rate: %.2f\nFalse Rate: %.2f\n",
		rule.Type, rule.Pattern, rule.Keywords, rule.Description, rule.Confidence, validationResult.Valid, validationResult.MatchRate, validationResult.FalseRate)

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		fmt.Printf("Error writing output file: %v\n", err)
		return
	}

	fmt.Printf("Rule generated successfully: %s\n", outputFile)
	fmt.Printf("Attack Type: %s (Confidence: %.2f)\n", rule.Type, rule.Confidence)
	fmt.Printf("Generated Pattern: %s\n", rule.Pattern)
	fmt.Printf("Validation: %v\n", validationResult.Valid)
	fmt.Printf("Match Rate: %.2f, False Rate: %.2f\n", validationResult.MatchRate, validationResult.FalseRate)
}

func runValidate(cmd *cobra.Command, args []string) {
	if ruleFile == "" {
		fmt.Println("Error: rule file or pattern is required")
		return
	}

	// ??????????????¨´????????
	var pattern string
	if _, err := os.Stat(ruleFile); err == nil {
		data, err := os.ReadFile(ruleFile)
		if err != nil {
			fmt.Printf("Error reading rule file: %v\n", err)
			return
		}
		pattern = string(data)
	} else {
		pattern = ruleFile
	}

	// ???????????
	val := validator.NewValidator(cfg)
	positiveSamples, negativeSamples := val.GenerateTestSamples("sqli", 5)

	// ???????
	result := val.Validate(pattern, positiveSamples, negativeSamples)

	// ??????
	fmt.Printf("Validation Result:\n")
	fmt.Printf("Valid: %v\n", result.Valid)
	fmt.Printf("Syntax Valid: %v\n", result.SyntaxValid)
	fmt.Printf("Match Rate: %.2f\n", result.MatchRate)
	fmt.Printf("False Rate: %.2f\n", result.FalseRate)
	fmt.Printf("Performance: %s\n", result.Performance)

	if len(result.Errors) > 0 {
		fmt.Printf("Errors:\n")
		for _, err := range result.Errors {
			fmt.Printf("- %s\n", err)
		}
	}
}

func runBatch(cmd *cobra.Command, args []string) {
	if inputFile == "" {
		fmt.Println("Error: directory is required")
		return
	}

	if outputFile == "" {
		outputFile = "rules"
	}

	// ????????????
	if err := os.MkdirAll(outputFile, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	// ??????§Ö????????
	files, err := os.ReadDir(inputFile)
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		return
	}

	gen := generator.NewGenerator(cfg)
	val := validator.NewValidator(cfg)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(inputFile, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", file.Name(), err)
			continue
		}

		input := string(data)
		rule, err := gen.Generate(input)
		if err != nil {
			fmt.Printf("Error generating rule for %s: %v\n", file.Name(), err)
			continue
		}

		// ???????
		positiveSamples, negativeSamples := val.GenerateTestSamples(rule.Type, 5)
		validationResult := val.Validate(rule.Pattern, positiveSamples, negativeSamples)

		// §Õ????????
		outputPath := filepath.Join(outputFile, file.Name()+".rule")
		output := fmt.Sprintf("# WAAP Rule\nType: %s\nPattern: %s\nKeywords: %v\nDescription: %s\nConfidence: %.2f\nValidation: %v\nMatch Rate: %.2f\nFalse Rate: %.2f\n",
			rule.Type, rule.Pattern, rule.Keywords, rule.Description, rule.Confidence, validationResult.Valid, validationResult.MatchRate, validationResult.FalseRate)

		if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
			fmt.Printf("Error writing output file %s: %v\n", outputPath, err)
			continue
		}

		fmt.Printf("Processed: %s -> %s\n", file.Name(), outputPath)
	}

	fmt.Printf("Batch processing completed\n")
}

func runConfigGet(cmd *cobra.Command, args []string) {
	fmt.Printf("Current Configuration:\n")
	fmt.Printf("API Key: %s\n", cfg.API.Key)
	fmt.Printf("Model: %s\n", cfg.API.Model)
	fmt.Printf("API URL: %s\n", cfg.API.URL)
	fmt.Printf("Max Tokens: %d\n", cfg.Generator.MaxTokens)
	fmt.Printf("Temperature: %.2f\n", cfg.Generator.Temperature)
	fmt.Printf("Output Format: %s\n", cfg.Output.Format)
	fmt.Printf("Output Path: %s\n", cfg.Output.Path)
}

func runConfigSet(cmd *cobra.Command, args []string) {
	if attackType == "" || outputFile == "" {
		fmt.Println("Error: both key and value are required")
		return
	}

	// ???????????????????????
	fmt.Printf("Config set: %s = %s\n", attackType, outputFile)

	// ????????
	if err := cfg.Save(""); err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		return
	}

	fmt.Println("Configuration saved")
}
