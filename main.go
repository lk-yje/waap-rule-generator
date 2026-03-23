package main

import (
	"fmt"
	"waap-rule-generator/pkg/llm"
)

func main() {
	// Test SQL injection samples
	sqlSamples := []string{
		"' UNION SELECT 1,2,3--",
		"admin' OR '1'='1'--",
		"' OR 1=1 #",
	}

	fmt.Println("=== SQL Injection Test ===")
	for _, sample := range sqlSamples {
		fmt.Printf("\nSample: %s\n", sample)
		rule, err := llm.GenerateRuleByLLM(sample)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		fmt.Printf("Rule: %s\n", rule)
	}

	// Test RCE samples
	rceSamples := []string{
		"eval('alert(1)')",
		"exec('ls -la')",
		"shell_exec('cat /etc/passwd')",
	}

	fmt.Println("\n\n=== RCE Test ===")
	for _, sample := range rceSamples {
		fmt.Printf("\nSample: %s\n", sample)
		rule, err := llm.GenerateRuleByLLM(sample)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		fmt.Printf("Rule: %s\n", rule)
	}
}
