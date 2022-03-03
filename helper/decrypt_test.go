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

package helper_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/minio/sio"
	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/libpak/crush"
	"github.com/sclevine/spec"
	"golang.org/x/crypto/hkdf"

	"github.com/paketo-buildpacks/encrypt-at-rest/v4/helper"
	"github.com/paketo-buildpacks/encrypt-at-rest/v4/internal"
)

func testDecrypt(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		decryptedPath string
		encryptedPath string
		key           string
		saltPath      string
	)

	it.Before(func() {
		var err error

		decryptedPath, err = ioutil.TempDir("", "decrypt-decrypted")
		Expect(err).NotTo(HaveOccurred())

		f, err := ioutil.TempFile("", "decrypt-encrypted")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		encryptedPath = f.Name()

		key = "E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60"

		f, err = ioutil.TempFile("", "decrypt-salt")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		saltPath = f.Name()
	})

	it.After(func() {
		Expect(os.RemoveAll(decryptedPath)).To(Succeed())
		Expect(os.RemoveAll(encryptedPath)).To(Succeed())
		Expect(os.RemoveAll(saltPath)).To(Succeed())
	})

	it("does nothing if $BPL_EAR_KEY is not set", func() {
		Expect(helper.Decrypt{}.Execute()).To(BeNil())
	})

	context("$BPL_EAR_KEY", func() {

		it.Before(func() {
			Expect(os.Setenv("BPL_EAR_KEY", key))
		})

		it.After(func() {
			Expect(os.Unsetenv("BPL_EAR_KEY")).To(Succeed())
		})

		it("return error if $BPI_EAR_SALT_PATH is not set", func() {
			_, err := helper.Decrypt{}.Execute()
			Expect(err).To(MatchError("$BPI_EAR_SALT_PATH must be set"))
		})

		context("$BPI_EAR_SALT_PATH", func() {

			it.Before(func() {
				Expect(os.Setenv("BPI_EAR_SALT_PATH", saltPath)).To(Succeed())
			})

			it.After(func() {
				Expect(os.Unsetenv("BPI_EAR_SALT_PATH")).To(Succeed())
			})

			it("return error if $BPI_EAR_ENCRYPTED_APPLICATION is not set", func() {
				_, err := helper.Decrypt{}.Execute()
				Expect(err).To(MatchError("$BPI_EAR_ENCRYPTED_APPLICATION must be set"))
			})

			context("$BPI_EAR_ENCRYPTED_APPLICATION", func() {

				it.Before(func() {
					Expect(os.Setenv("BPI_EAR_ENCRYPTED_APPLICATION", encryptedPath)).To(Succeed())
				})

				it.After(func() {
					Expect(os.Unsetenv("BPI_EAR_ENCRYPTED_APPLICATION")).To(Succeed())
				})

				it("return error if $BPI_EAR_DECRYPTED_APPLICATION is not set", func() {
					_, err := helper.Decrypt{}.Execute()
					Expect(err).To(MatchError("$BPI_EAR_DECRYPTED_APPLICATION must be set"))
				})

				context("$BPI_EAR_DECRYPTED_APPLICATION", func() {

					it.Before(func() {
						Expect(os.Setenv("BPI_EAR_DECRYPTED_APPLICATION", decryptedPath)).To(Succeed())
					})

					it.After(func() {
						Expect(os.Unsetenv("BPI_EAR_DECRYPTED_APPLICATION")).To(Succeed())
					})

					it("decrypts application", func() {
						primary, err := hex.DecodeString(key)
						Expect(err).NotTo(HaveOccurred())

						var salt [32]byte
						_, err = io.ReadFull(rand.Reader, salt[:])
						Expect(err).NotTo(HaveOccurred())
						Expect(ioutil.WriteFile(saltPath, salt[:], 0644)).To(Succeed())

						var key [32]byte
						kdf := hkdf.New(sha256.New, primary, salt[:], nil)
						_, err = io.ReadFull(kdf, key[:])
						Expect(err).NotTo(HaveOccurred())

						out, err := os.OpenFile(encryptedPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
						Expect(err).NotTo(HaveOccurred())

						w, err := sio.EncryptWriter(out, sio.Config{Key: key[:]})
						Expect(err).NotTo(HaveOccurred())

						file := filepath.Join(decryptedPath, "fixture-marker")
						Expect(ioutil.WriteFile(file, []byte{}, 0644)).To(Succeed())
						Expect(crush.CreateTar(w, decryptedPath)).To(Succeed())
						Expect(os.RemoveAll(file)).To(Succeed())

						Expect(w.Close()).To(Succeed())

						Expect(helper.Decrypt{}.Execute()).To(BeNil())
						Expect(filepath.Join(decryptedPath, "fixture-marker")).To(BeARegularFile())
					})

					if internal.IsRoot() {
						return
					}

					it("returns error if decrypted application path is not writable", func() {
						Expect(os.Chmod(decryptedPath, 0555)).To(Succeed())

						_, err := helper.Decrypt{}.Execute()
						Expect(err).To(MatchError(fmt.Sprintf("unable to write to %s", decryptedPath)))
					})
				})
			})
		})
	})
}
