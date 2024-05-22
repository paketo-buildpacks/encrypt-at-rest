/*
 * Copyright 2018-2024 the original author or authors.
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
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"
	"github.com/minio/sio"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/crush"
	"github.com/paketo-buildpacks/libpak/sherpa"
	"golang.org/x/crypto/hkdf"
)

type Encrypt struct {
	ApplicationPath  string
	Key              []byte
	LayerContributor libpak.LayerContributor
	Logger           bard.Logger
}

func NewEncrypt(applicationPath string, key []byte) (Encrypt, error) {
	l, err := sherpa.NewFileListing(applicationPath)
	if err != nil {
		return Encrypt{}, fmt.Errorf("unable to create file listing for %s\n%w", applicationPath, err)
	}
	expected := map[string][]sherpa.FileEntry{"files": l}

	return Encrypt{
		ApplicationPath: applicationPath,
		Key:             key,
		LayerContributor: libpak.NewLayerContributor("Encrypt Application", expected, libcnb.LayerTypes{
			Launch: true,
		}),
	}, nil
}

func (e Encrypt) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	e.LayerContributor.Logger = e.Logger

	layer, err := e.LayerContributor.Contribute(layer, func() (libcnb.Layer, error) {
		var salt [32]byte
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to generate salt\n%w", err)
		}

		e.Logger.Body("Writing salt")
		file := filepath.Join(layer.Path, "salt")
		if err := os.WriteFile(file, salt[:], 0644); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to write %s\n%w", file, err)
		}
		layer.LaunchEnvironment.Default("BPI_EAR_SALT_PATH", file)

		var key [32]byte
		kdf := hkdf.New(sha256.New, e.Key, salt[:], nil)
		if _, err := io.ReadFull(kdf, key[:]); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to derive encryption key\n%w", err)
		}

		file = filepath.Join(layer.Path, "application.tar.dare")
		out, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to open %s\n%w", file, err)
		}
		defer out.Close()

		w, err := sio.EncryptWriter(out, sio.Config{Key: key[:]})
		if err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to create encrypted writer\n%w", err)
		}

		e.Logger.Bodyf("Encrypting to %s", file)
		if err := crush.CreateTar(w, e.ApplicationPath); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to create TAR from %s\n%w", e.ApplicationPath, err)
		}

		if err = w.Close(); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to finalize encryption\n%w", err)
		}

		layer.LaunchEnvironment.Default("BPI_EAR_ENCRYPTED_APPLICATION", file)
		layer.LaunchEnvironment.Default("BPI_EAR_DECRYPTED_APPLICATION", e.ApplicationPath)

		return layer, nil
	})
	if err != nil {
		return libcnb.Layer{}, fmt.Errorf("unable to contribute layer\n%w", err)
	}

	e.Logger.Header("Removing source code")
	cs, err := os.ReadDir(e.ApplicationPath)
	if err != nil {
		return libcnb.Layer{}, fmt.Errorf("unable to list children of %s\n%w", e.ApplicationPath, err)
	}
	for _, c := range cs {
		file := filepath.Join(e.ApplicationPath, c.Name())
		if err := os.RemoveAll(file); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to remove %s\n%w", file, err)
		}
	}

	return layer, nil
}

func (Encrypt) Name() string {
	return "encrypt"
}
