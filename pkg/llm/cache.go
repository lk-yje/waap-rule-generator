package llm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type RuleCache struct {
	cache     map[string]map[string]string // category -> input -> rule
	cacheFile string
	mutex     sync.RWMutex
}

func NewRuleCache(cacheFile string) *RuleCache {
	cache := &RuleCache{
		cache:     make(map[string]map[string]string),
		cacheFile: cacheFile,
	}
	cache.load()
	return cache
}

func (c *RuleCache) Get(category, input string) (string, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if categoryMap, exists := c.cache[category]; exists {
		if rule, exists := categoryMap[input]; exists {
			return rule, true
		}
	}
	return "", false
}

func (c *RuleCache) Set(category, input, rule string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, exists := c.cache[category]; !exists {
		c.cache[category] = make(map[string]string)
	}
	c.cache[category][input] = rule
	c.save()
}

func (c *RuleCache) GetAllByCategory(category string) map[string]string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if categoryMap, exists := c.cache[category]; exists {
		result := make(map[string]string)
		for k, v := range categoryMap {
			result[k] = v
		}
		return result
	}
	return make(map[string]string)
}

func (c *RuleCache) GetCategories() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	categories := make([]string, 0, len(c.cache))
	for category := range c.cache {
		categories = append(categories, category)
	}
	return categories
}

func (c *RuleCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	total := 0
	for _, categoryMap := range c.cache {
		total += len(categoryMap)
	}
	return total
}

func (c *RuleCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache = make(map[string]map[string]string)
	c.save()
}

func (c *RuleCache) load() {
	if _, err := os.Stat(c.cacheFile); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	if err := json.Unmarshal(data, &c.cache); err != nil {
		fmt.Printf("Error unmarshaling cache: %v\n", err)
	}
}

func (c *RuleCache) save() {
	dir := filepath.Dir(c.cacheFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Error creating cache directory: %v\n", err)
		return
	}

	data, err := json.MarshalIndent(c.cache, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling cache: %v\n", err)
		return
	}

	if err := os.WriteFile(c.cacheFile, data, 0644); err != nil {
		fmt.Printf("Error saving cache: %v\n", err)
	}
}
