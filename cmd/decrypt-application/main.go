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

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/paketo-buildpacks/encrypt-at-rest/decrypt"
	"github.com/paketo-buildpacks/libpak/sherpa"
	"github.com/spf13/pflag"
)

func main() {
	sherpa.Execute(func() error {
		s, ok := os.LookupEnv("BPL_EAR_KEY")
		if !ok {
			return nil
		}

		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("unable to decode key\n%w", err)
		}

		d := decrypt.Decrypt{
			Key: b,
		}

		flagSet := pflag.NewFlagSet("Decrypt Application", pflag.ExitOnError)
		flagSet.StringVar(&d.DecryptedApplicationPath, "decrypted-application", "", "path to write decrypted application to")
		flagSet.StringVar(&d.EncryptedApplicationPath, "encrypted-application", "", "path to read encrypted application from")
		flagSet.StringVar(&d.InitialVectorPath, "initial-vector", "", "path to file containing the initial vector used for decryption")

		if err := flagSet.Parse(os.Args[1:]); err != nil {
			return fmt.Errorf("unable to parse flags\n%w", err)
		}

		return d.Execute()
	})
}
