/*
 * Copyright 2018-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dare

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

//go:generate mockery -name KeyProvider -case=underscore

type KeyProvider interface {
	Detect(context libcnb.DetectContext, result *libcnb.DetectResult) error
	Key() ([]byte, error)
	Participate(resolver libpak.PlanEntryResolver) (bool, error)
}

type EnvironmentVariableKeyProvider struct {
	Logger bard.Logger
}

func (EnvironmentVariableKeyProvider) Detect(context libcnb.DetectContext, result *libcnb.DetectResult) error {
	if _, ok := os.LookupEnv("BP_EAR_KEY"); !ok {
		return nil
	}

	result.Pass = true
	result.Plans = append(result.Plans, libcnb.BuildPlan{
		Provides: []libcnb.BuildPlanProvide{
			{Name: "encrypt-at-rest"},
		},
		Requires: []libcnb.BuildPlanRequire{
			{Name: "encrypt-at-rest", Metadata: map[string]interface{}{"type": "environment-variable"}},
		},
	})

	return nil
}

func (EnvironmentVariableKeyProvider) Key() ([]byte, error) {
	s := os.Getenv("BP_EAR_KEY")
	return hex.DecodeString(s)
}

func (e EnvironmentVariableKeyProvider) Participate(resolver libpak.PlanEntryResolver) (bool, error) {
	if f, ok, err := resolver.Resolve("encrypt-at-rest"); err != nil {
		return false, fmt.Errorf("unable to resolve gradle plan entry\n%w", err)
	} else if ok && f.Metadata["type"].(string) == "environment-variable" {
		e.Logger.Body(bard.FormatUserConfig("BP_EAR_KEY", "the AES hex encoded encryption key", "<none>"))
		e.Logger.Body(bard.FormatUserConfig("BPL_EAR_KEY", "the AES hex encoded encryption key", "<none>"))
		return true, nil
	}

	return false, nil
}
