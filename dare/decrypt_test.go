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

package dare_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/encrypt-at-rest/dare"
	"github.com/sclevine/spec"
)

func testDecrypt(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		ctx libcnb.BuildContext
	)

	it.Before(func() {
		var err error

		ctx.Application.Path, err = ioutil.TempDir("", "decrypt-application")
		Expect(err).NotTo(HaveOccurred())

		ctx.Buildpack.Info.Name = "test-name"

		ctx.Buildpack.Path, err = ioutil.TempDir("", "decrypt-buildpack")
		Expect(err).NotTo(HaveOccurred())

		ctx.Layers.Path, err = ioutil.TempDir("", "decrypt-layers")
		Expect(err).NotTo(HaveOccurred())
	})

	it.After(func() {
		Expect(os.RemoveAll(ctx.Application.Path)).To(Succeed())
		Expect(os.RemoveAll(ctx.Buildpack.Path)).To(Succeed())
		Expect(os.RemoveAll(ctx.Layers.Path)).To(Succeed())
	})

	it("contributes decrypt", func() {
		Expect(os.MkdirAll(filepath.Join(ctx.Buildpack.Path, "bin"), 0755)).To(Succeed())
		Expect(ioutil.WriteFile(filepath.Join(ctx.Buildpack.Path, "bin", "decrypt-application"), []byte{}, 0755)).To(Succeed())

		d := dare.NewDecrypt(ctx.Application.Path, ctx.Buildpack, &ctx.Plan)
		layer, err := ctx.Layers.Layer("test-layer")
		Expect(err).NotTo(HaveOccurred())

		layer, err = d.Contribute(layer)
		Expect(err).NotTo(HaveOccurred())

		Expect(layer.Launch).To(BeTrue())
		Expect(filepath.Join(layer.Path, "bin", "decrypt-application")).To(BeARegularFile())
		Expect(layer.Profile["decrypt-application.sh"]).To(Equal(fmt.Sprintf(`printf "Decrypting application\n"

decrypt-application \
  --decrypted-application "%s" \
  --encrypted-application "%s" \
  --salt "%s"
`,
			ctx.Application.Path,
			filepath.Join(ctx.Layers.Path, "encrypt", "application.tar.dare"),
			filepath.Join(ctx.Layers.Path, "encrypt", "salt"))))
	})

}
