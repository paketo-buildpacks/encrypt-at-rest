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
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/encrypt-at-rest/decrypt"
	"github.com/sclevine/spec"
)

func testDecrypt(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		decrypted     string
		encrypted     string
		initialVector string
	)

	it.Before(func() {
		var err error

		decrypted, err = ioutil.TempDir("", "decrypt-decrypted")
		Expect(err).NotTo(HaveOccurred())

		f, err := ioutil.TempFile("", "decrypt-encrypted")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		encrypted = f.Name()

		f, err = ioutil.TempFile("", "decrypt-initial-vector")
		Expect(err).NotTo(HaveOccurred())
		Expect(f.Close()).To(Succeed())
		initialVector = f.Name()
	})

	it.After(func() {
		Expect(os.RemoveAll(decrypted)).To(Succeed())
		Expect(os.RemoveAll(encrypted)).To(Succeed())
		Expect(os.RemoveAll(initialVector)).To(Succeed())
	})

	it("decrypts application", func() {
		out, err := os.OpenFile(encrypted, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		Expect(err).NotTo(HaveOccurred())

		key, err := hex.DecodeString("E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60")
		Expect(err).NotTo(HaveOccurred())

		block, err := aes.NewCipher(key)
		Expect(err).NotTo(HaveOccurred())

		iv := make([]byte, aes.BlockSize)
		_, err = io.ReadFull(rand.Reader, iv)
		Expect(err).NotTo(HaveOccurred())
		Expect(ioutil.WriteFile(initialVector, iv, 0644)).To(Succeed())

		t := tar.NewWriter(cipher.StreamWriter{S: cipher.NewCFBEncrypter(block, iv), W: out})
		err = t.WriteHeader(&tar.Header{Name: "fixture-marker"})
		Expect(err).NotTo(HaveOccurred())
		_, err = t.Write([]byte{})
		Expect(err).NotTo(HaveOccurred())

		Expect(t.Close()).To(Succeed())
		Expect(out.Close()).To(Succeed())

		d := decrypt.Decrypt{
			DecryptedApplicationPath: decrypted,
			EncryptedApplicationPath: encrypted,
			InitialVectorPath:        initialVector,
			Key:                      key,
		}

		Expect(d.Execute()).To(Succeed())
		Expect(filepath.Join(decrypted, "fixture-marker")).To(BeARegularFile())
	})
}
