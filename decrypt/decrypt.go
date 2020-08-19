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
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/heroku/color"
	"github.com/minio/sio"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/crush"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/unix"
)

type Decrypt struct {
	Logger bard.Logger
}

func (d Decrypt) Execute() (map[string]string, error) {
	s, ok := os.LookupEnv("BPL_EAR_KEY")
	if !ok {
		return nil, nil
	}

	primary, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key\n%w", err)
	}

	file, ok := os.LookupEnv("BPI_EAR_SALT_PATH")
	if !ok {
		return nil, fmt.Errorf("$BPI_EAR_SALT_PATH must be set")
	}
	salt, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s\n%w", file, err)
	}

	file, ok = os.LookupEnv("BPI_EAR_ENCRYPTED_APPLICATION")
	if !ok {
		return nil, fmt.Errorf("$BPI_EAR_ENCRYPTED_APPLICATION must be set")
	}
	in, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s\n%w", file, err)
	}
	defer in.Close()

	file, ok = os.LookupEnv("BPI_EAR_DECRYPTED_APPLICATION")
	if !ok {
		return nil, fmt.Errorf("$BPI_EAR_DECRYPTED_APPLICATION must be set")
	}
	if unix.Access(file, unix.W_OK) != nil {
		d.Logger.Info(color.New(color.FgRed, color.Bold).Sprintf("Unable to decrypt application because %s is not writable", file))
		return nil, fmt.Errorf("unable to write to %s", file)
	}
	out := file

	var key [32]byte
	kdf := hkdf.New(sha256.New, primary, salt[:], nil)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return nil, fmt.Errorf("unable to derive encryption key\n%w", err)
	}

	r, err := sio.DecryptReader(in, sio.Config{Key: key[:]})
	if err != nil {
		return nil, fmt.Errorf("unable to create encrypted reader\n%w", err)
	}

	if err := crush.ExtractTar(r, out, 0); err != nil {
		return nil, fmt.Errorf("unable to extract TAR %s to %s\n%w", in.Name(), out, err)
	}

	return nil, nil
}
