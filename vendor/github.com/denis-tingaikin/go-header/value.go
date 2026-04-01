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
	"errors"
	"fmt"
	"strings"
)

type Value interface {
	Calculate(map[string]Value) error
	Get() string
	Raw() string
	Clone() Value
}

func calculateValue(calculable Value, values map[string]Value) (string, error) {
	sb := strings.Builder{}
	r := calculable.Raw()
	var endIndex int
	var startIndex int
	for startIndex = strings.Index(r, "{{"); startIndex >= 0; startIndex = strings.Index(r, "{{") {
		_, _ = sb.WriteString(r[:startIndex])
		endIndex = strings.Index(r, "}}")
		if endIndex < 0 {
			return "", errors.New("missed value ending")
		}
		subVal := strings.TrimSpace(r[startIndex+2 : endIndex])
		subVal, _ = strings.CutPrefix(subVal, ".")
		if val := values[subVal]; val != nil {
			if err := val.Calculate(values); err != nil {
				return "", err
			}
			sb.WriteString(val.Get())
		} else {
			return "", fmt.Errorf("unknown value name %v", subVal)
		}
		endIndex += 2
		r = r[endIndex:]
	}
	_, _ = sb.WriteString(r)
	return sb.String(), nil
}

type ConstValue struct {
	RawValue, Value string
}

func (c *ConstValue) Calculate(values map[string]Value) error {
	v, err := calculateValue(c, values)
	if err != nil {
		return err
	}
	c.Value = v
	return nil
}

func (c *ConstValue) Raw() string {
	return c.RawValue
}

func (c *ConstValue) Clone() Value {
	return &ConstValue{
		RawValue: c.RawValue,
		Value:    c.Value,
	}
}

func (c *ConstValue) Get() string {
	if c.Value != "" {
		return c.Value
	}
	return c.RawValue
}

func (c *ConstValue) String() string {
	return c.Get()
}

type RegexpValue struct {
	RawValue, Value string
}

func (r *RegexpValue) Clone() Value {
	return &RegexpValue{
		Value:    r.Value,
		RawValue: r.RawValue,
	}
}

func (r *RegexpValue) Calculate(values map[string]Value) error {
	v, err := calculateValue(r, values)
	if err != nil {
		return err
	}
	r.Value = v
	return nil
}

func (r *RegexpValue) Raw() string {
	return r.RawValue
}
func (r *RegexpValue) Get() string {
	if r.Value != "" {
		return r.Value
	}
	return r.RawValue
}

func (r *RegexpValue) String() string {
	return r.Get()
}

var _ Value = &ConstValue{}
var _ Value = &RegexpValue{}
