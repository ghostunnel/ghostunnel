// Copyright (c) 2020-2025 Denis Tingaikin
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goheader

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Experimental represents config params for enabling experimental / work in progress features
type Experimental struct {
	// CGO if true enables support for cgo files. Currently positioning of issues can be float.
	CGO bool `yaml:"cgo"`
}

// Config represents go-header linter setup parameters
type Config struct {
	// Values is map of values. Supports two types 'const` and `regexp`. Values can be used recursively.
	// DEPRECATED: Use Vars instead.
	Values map[string]map[string]string `yaml:"values"`
	// Template is template for checking. Uses values.
	Template string `yaml:"template"`
	// TemplatePath path to the template file. Useful if need to load the template from a specific file.
	TemplatePath string `yaml:"template-path"`
	// Vars is map of values. Values can be used recursively.
	Vars map[string]string `yaml:"vars"`
	// Delims represents a string marker for values. The default is "{{}}".
	Delims string `yaml:"delims"`
	// Parallel means a number of goroutines to proccess files. Default runtime.NumCPU()
	Parallel int `yaml:"parallel"`
	// Experimental is config for enabling experimental / work in progress features.
	Experimental Experimental `yaml:"experimental"`
}

func (c *Config) GetDelims() string {
	if c.Delims == "" {
		return "{{}}"
	}
	return c.Delims
}

func (c *Config) GetParallel() int {
	if c.Parallel <= 0 {
		return runtime.NumCPU()
	}
	return c.Parallel
}

func (c *Config) GetValues() (map[string]Value, error) {
	result := builtInValues()

	createConst := func(raw string) Value {
		return &ConstValue{RawValue: raw}
	}

	createRegexp := func(raw string) Value {
		return &RegexpValue{RawValue: raw}
	}

	appendValues := func(m map[string]string, create func(string) Value) {
		for k, v := range m {
			result[strings.ToLower(k)] = create(v)
			result[strings.ToUpper(k)] = create(v)
		}
	}

	appendValues(c.Values["const"], createConst)
	appendValues(c.Values["regexp"], createRegexp)
	appendValues(c.Vars, createRegexp)

	return result, nil
}

func builtInValues() map[string]Value {
	var result = make(map[string]Value)
	year := fmt.Sprint(time.Now().Year())
	result["YEAR_RANGE"] = &RegexpValue{
		RawValue: `((20\d\d\-{{.YEAR}})|({{.YEAR}}))`,
	}
	result["YEAR"] = &ConstValue{
		RawValue: year,
	}
	return result
}

func (c *Config) GetTemplate() (string, error) {
	var tmpl, err = c.getTemplate()

	if err != nil {
		return tmpl, err
	}

	return migrateOldConfig(tmpl, c.GetDelims()), nil
}

func (c *Config) getTemplate() (string, error) {
	if c.Template != "" {
		return c.Template, nil
	}
	if c.TemplatePath == "" {
		return "", nil
	}

	b, err := os.ReadFile(c.TemplatePath)
	if err != nil {
		return "", err
	}

	c.Template = strings.TrimSpace(string(b))

	return c.Template, nil
}

func migrateOldConfig(input string, delims string) string {
	left := delims[:len(delims)/2]
	right := delims[len(delims)/2:]

	// Regular expression to find all {{...}} patterns
	exp := regexp.MustCompile(regexp.QuoteMeta("{{") + `\s*([^}]+)\s*` + regexp.QuoteMeta("}}"))

	// Replace each match with the converted version
	result := exp.ReplaceAllStringFunc(input, func(match string) string {
		// Extract the inner content (between {{ and }})
		inner := match[2 : len(match)-2]
		inner = strings.TrimSpace(inner)

		if strings.HasPrefix(inner, ".") {
			return fmt.Sprintf("%v %v %v", left, inner, right)
		}

		// Replace spaces with underscores
		convertedInner := strings.ReplaceAll(inner, " ", "_")

		// Add the dot prefix
		return fmt.Sprintf("%v .%v %v", left, convertedInner, right)
	})

	return result
}

func (c *Config) FillSettings(settings *Settings) error {
	delimiters := c.GetDelims()
	if delimiters != "" && len(delimiters)%2 == 0 {
		settings.LeftDelim = delimiters[:len(delimiters)/2]
		settings.RightDelim = delimiters[len(delimiters)/2:]
	}

	if settings.LeftDelim == "" {
		settings.LeftDelim = "{{"
	}
	if settings.RightDelim == "" {
		settings.RightDelim = "}}"
	}

	tmpl, err := c.GetTemplate()
	if err != nil {
		return err
	}
	if tmpl != "" {
		settings.Template = tmpl
	}

	vals, err := c.GetValues()
	if err != nil {
		return err
	}

	if len(vals) > 0 {
		settings.Values = vals
	}

	settings.Parallel = c.GetParallel()
	settings.CGO = c.Experimental.CGO

	return nil
}

func Parse(data string) (*Config, error) {
	b, err := os.ReadFile(data)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	err = yaml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

type Settings struct {
	Values                map[string]Value
	Template              string
	LeftDelim, RightDelim string
	Parallel              int
	CGO                   bool
}

func (c *Settings) SetTemplate(tmplStr, tmplPath string) error {
	if tmplStr != "" {
		c.Template = tmplStr
		return nil
	}

	if tmplPath == "" {
		c.Template = ""
		return nil
	}

	b, err := os.ReadFile(tmplPath)
	if err != nil {
		return err
	}

	c.Template = strings.TrimSpace(string(b))

	return nil
}

func (c *Settings) SetDelimiters(left, right string) {
	c.LeftDelim = left
	if left == "" {
		c.LeftDelim = "{{"
	}

	c.RightDelim = right
	if right == "" {
		c.RightDelim = "}}"
	}
}

func (c *Settings) SetValues(values map[string]string) {
	result := builtInValues()

	appendValues := func(m map[string]string, create func(string) Value) {
		for k, v := range m {
			result[strings.ToLower(k)] = create(v)
			result[strings.ToUpper(k)] = create(v)
		}
	}

	appendValues(values, func(raw string) Value {
		return &RegexpValue{RawValue: raw}
	})

	c.Values = result
}
