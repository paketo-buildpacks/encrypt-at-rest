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
	"fmt"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

type Build struct {
	Logger       bard.Logger
	KeyProviders []KeyProvider
}

func (b Build) Build(context libcnb.BuildContext) (libcnb.BuildResult, error) {
	b.Logger.Title(context.Buildpack)
	result := libcnb.NewBuildResult()

	_, err := libpak.NewConfigurationResolver(context.Buildpack, &b.Logger)
	if err != nil {
		return libcnb.BuildResult{}, fmt.Errorf("unable to create configuration resolver\n%w", err)
	}

	pr := libpak.PlanEntryResolver{Plan: context.Plan}

	for _, k := range b.KeyProviders {
		if ok, err := k.Participate(pr); err != nil {
			return libcnb.BuildResult{}, fmt.Errorf("unable to determine participation\n%w", err)
		} else if !ok {
			continue
		}

		key, err := k.Key(context)
		if err != nil {
			return libcnb.BuildResult{}, fmt.Errorf("unable to get encryption key\n%w", err)
		}

		e, err := NewEncrypt(context.Application.Path, key)
		if err != nil {
			return libcnb.BuildResult{}, fmt.Errorf("unable to create encrypt layer\n%w", err)
		}
		e.Logger = b.Logger
		result.Layers = append(result.Layers, e)

		h := libpak.NewHelperLayerContributor(context.Buildpack, result.Plan, "decrypt-application")
		h.Logger = b.Logger
		result.Layers = append(result.Layers, h)
	}

	return result, nil
}
