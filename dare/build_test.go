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
	"io/ioutil"
	"os"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/sclevine/spec"
	"github.com/stretchr/testify/mock"

	"github.com/paketo-buildpacks/encrypt-at-rest/dare"
	"github.com/paketo-buildpacks/encrypt-at-rest/dare/mocks"
)

func testBuild(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		build dare.Build
		ctx   libcnb.BuildContext
		kp    *mocks.KeyProvider
	)

	it.Before(func() {
		var err error

		ctx.Application.Path, err = ioutil.TempDir("", "build")
		Expect(err).NotTo(HaveOccurred())

		kp = &mocks.KeyProvider{}
		build.KeyProviders = append(build.KeyProviders, kp)
	})

	it.After(func() {
		Expect(os.RemoveAll(ctx.Application.Path)).To(Succeed())
	})

	it("does not contribute with no participating key provider", func() {
		kp.On("Participate", mock.Anything).Return(false, nil)

		Expect(build.Build(ctx)).To(Equal(libcnb.NewBuildResult()))
	})

	it("contributes ", func() {
		kp.On("Participate", mock.Anything).Return(true, nil)
		kp.On("Key", mock.Anything).Return([]byte{}, nil)

		result, err := build.Build(ctx)
		Expect(err).NotTo(HaveOccurred())

		Expect(result.Layers).To(HaveLen(2))
		Expect(result.Layers[0].Name()).To(Equal("encrypt"))
		Expect(result.Layers[1].Name()).To(Equal("decrypt-application"))
	})

}
