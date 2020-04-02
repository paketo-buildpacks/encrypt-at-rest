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

package decrypt

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/minio/sio"
	"github.com/paketo-buildpacks/libpak/crush"
	"golang.org/x/crypto/hkdf"
)

type Decrypt struct {
	DecryptedApplicationPath string
	EncryptedApplicationPath string
	Key                      []byte
	SaltPath                 string
}

func (d Decrypt) Execute() error {
	salt, err := ioutil.ReadFile(d.SaltPath)
	if err != nil {
		return fmt.Errorf("uanble to read salt\n%w", err)
	}

	var key [32]byte
	kdf := hkdf.New(sha256.New, d.Key, salt[:], nil)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return fmt.Errorf("unable to derive encryption key\n%w", err)
	}

	in, err := os.Open(d.EncryptedApplicationPath)
	if err != nil {
		return fmt.Errorf("unable to open %s\n%w", d.EncryptedApplicationPath, err)
	}
	defer in.Close()

	r, err := sio.DecryptReader(in, sio.Config{Key: key[:]})
	if err != nil {
		return fmt.Errorf("unable to create encrypted reader\n%w", err)
	}

	if err := crush.ExtractTar(r, d.DecryptedApplicationPath, 0); err != nil {
		return fmt.Errorf("unable to extract TAR %s to %s\n%w", d.EncryptedApplicationPath, d.DecryptedApplicationPath, err)
	}

	return nil
}
