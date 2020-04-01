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

package ear

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"
	_ "github.com/paketo-buildpacks/encrypt-at-rest/ear/statik"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/sherpa"
)

type Decrypt struct {
	ApplicationPath  string
	LayerContributor libpak.HelperLayerContributor
	Logger           bard.Logger
}

func NewDecrypt(applicationPath string, buildpack libcnb.Buildpack, plan *libcnb.BuildpackPlan) Decrypt {
	return Decrypt{
		ApplicationPath: applicationPath,
		LayerContributor: libpak.NewHelperLayerContributor(filepath.Join(buildpack.Path, "bin", "decrypt-application"),
			"Decrypt Application", buildpack.Info, plan),
	}
}

//go:generate statik -src . -include *.sh

func (d Decrypt) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	d.LayerContributor.Logger = d.Logger

	return d.LayerContributor.Contribute(layer, func(artifact *os.File) (libcnb.Layer, error) {
		d.Logger.Bodyf("Copying to %s", layer.Path)

		if err := sherpa.CopyFile(artifact, filepath.Join(layer.Path, "bin", "decrypt-application")); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to copy\n%w", err)
		}

		e := filepath.Join(filepath.Dir(layer.Path), "encrypt")
		s, err := sherpa.TemplateFile("/decrypt-application.sh", map[string]interface{}{
			"decryptedApplication": d.ApplicationPath,
			"encryptedApplication": filepath.Join(e, "application.tar.aes"),
			"initialVector":        filepath.Join(e, "initial-vector"),
		})
		if err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to load decrypt-application.sh\n%w", err)
		}

		layer.Profile.Add("decrypt-application.sh", s)

		layer.Launch = true
		return layer, nil
	})
}

func (d Decrypt) Name() string {
	return "decrypt"
}
