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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/paketo-buildpacks/libpak/crush"
)

type Decrypt struct {
	DecryptedApplicationPath string
	EncryptedApplicationPath string
	InitialVectorPath        string
	Key                      []byte
}

func (d Decrypt) Execute() error {
	block, err := aes.NewCipher(d.Key)
	if err != nil {
		return fmt.Errorf("unable to create new cipher\n%w", err)
	}

	in, err := os.Open(d.EncryptedApplicationPath)
	if err != nil {
		return fmt.Errorf("unable to open %s\n%w", d.EncryptedApplicationPath, err)
	}
	defer in.Close()

	iv, err := ioutil.ReadFile(d.InitialVectorPath)
	if err != nil {
		return fmt.Errorf("unable to open %s\n%w", d.InitialVectorPath, err)
	}

	r := cipher.StreamReader{
		S: cipher.NewCFBDecrypter(block, iv),
		R: in,
	}
	defer in.Close()

	if err := crush.ExtractTar(r, d.DecryptedApplicationPath, 0); err != nil {
		return fmt.Errorf("unable to extract TAR to %s\n%w", d.DecryptedApplicationPath, err)
	}

	return nil
}
