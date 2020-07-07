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

package decrypt_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/paketo-buildpacks/encrypt-at-rest/decrypt"
)

func testDecrypt(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		decryptedPath string
		encryptedPath string
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

	it("decrypts application", func() {
		master, err := hex.DecodeString("E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60")
		Expect(err).NotTo(HaveOccurred())

		var salt [32]byte
		_, err = io.ReadFull(rand.Reader, salt[:])
		Expect(err).NotTo(HaveOccurred())
		Expect(ioutil.WriteFile(saltPath, salt[:], 0644)).To(Succeed())

		var key [32]byte
		kdf := hkdf.New(sha256.New, master, salt[:], nil)
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

		d := decrypt.Decrypt{
			DecryptedApplicationPath: decryptedPath,
			EncryptedApplicationPath: encryptedPath,
			Key:                      master,
			SaltPath:                 saltPath,
		}

		Expect(d.Execute()).To(Succeed())
		Expect(filepath.Join(decryptedPath, "fixture-marker")).To(BeARegularFile())
	})
}
