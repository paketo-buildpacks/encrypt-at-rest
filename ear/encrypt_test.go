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

package ear_test

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/encrypt-at-rest/ear"
	"github.com/sclevine/spec"
)

func testEncrypt(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		ctx libcnb.BuildContext
	)

	it.Before(func() {
		var err error

		ctx.Application.Path, err = ioutil.TempDir("", "encrypt-application")
		Expect(err).NotTo(HaveOccurred())

		ctx.Layers.Path, err = ioutil.TempDir("", "encrypt-layers")
		Expect(err).NotTo(HaveOccurred())
	})

	it.After(func() {
		Expect(os.RemoveAll(ctx.Application.Path)).To(Succeed())
		Expect(os.RemoveAll(ctx.Layers.Path)).To(Succeed())
	})

	it("contributes encrypt", func() {
		Expect(ioutil.WriteFile(filepath.Join(ctx.Application.Path, "fixture-marker"), []byte{}, 0644)).To(Succeed())

		key, err := hex.DecodeString("E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60")
		Expect(err).NotTo(HaveOccurred())

		e, err := ear.NewEncrypt(ctx.Application.Path, key)
		Expect(err).NotTo(HaveOccurred())

		layer, err := ctx.Layers.Layer("test-layer")
		Expect(err).NotTo(HaveOccurred())

		layer, err = e.Contribute(layer)
		Expect(err).NotTo(HaveOccurred())

		Expect(layer.Launch).To(BeTrue())
		Expect(filepath.Join(layer.Path, "application.tar.aes")).To(BeARegularFile())
		Expect(filepath.Join(layer.Path, "initial-vector")).To(BeARegularFile())

		b, err := ioutil.ReadFile(filepath.Join(layer.Path, "application.tar.aes"))
		Expect(err).NotTo(HaveOccurred())
		iv, err := ioutil.ReadFile(filepath.Join(layer.Path, "initial-vector"))
		Expect(err).NotTo(HaveOccurred())
		block, err := aes.NewCipher(key)
		Expect(err).NotTo(HaveOccurred())
		r := cipher.StreamReader{S: cipher.NewCFBDecrypter(block, iv), R: bytes.NewBuffer(b)}

		var files []string
		t := tar.NewReader(r)
		for {
			f, err := t.Next()
			if err != nil && err == io.EOF {
				break
			}
			Expect(err).NotTo(HaveOccurred())

			files = append(files, f.Name)
		}

		Expect(files).To(ContainElement("fixture-marker"))
	})

}
