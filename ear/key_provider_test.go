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
	"encoding/hex"
	"os"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/encrypt-at-rest/ear"
	"github.com/paketo-buildpacks/libpak"
	"github.com/sclevine/spec"
)

func testKeyProvider(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect
	)

	context("Build", func() {
		context("EnvironmentVariableKeyProvider", func() {
			var (
				kp ear.EnvironmentVariableKeyProvider
			)
			context("BP_EAR_KEY", func() {
				it.Before(func() {
					Expect(os.Setenv("BP_EAR_KEY", "E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60")).To(Succeed())
				})

				it.After(func() {
					Expect(os.Unsetenv("BP_EAR_KEY")).To(Succeed())
				})

				it("returns key", func() {
					b, err := hex.DecodeString("E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60")
					Expect(err).NotTo(HaveOccurred())

					Expect(kp.Key()).To(Equal(b))
				})
			})

			it("it participates", func() {
				pr := libpak.PlanEntryResolver{Plan: libcnb.BuildpackPlan{
					Entries: []libcnb.BuildpackPlanEntry{
						{Name: "encrypt-at-rest", Metadata: map[string]interface{}{"type": "environment-variable"}},
					},
				}}

				Expect(kp.Participate(pr)).To(BeTrue())
			})

		})
	})

	context("Detect", func() {
		var (
			ctx    libcnb.DetectContext
			result libcnb.DetectResult
		)

		context("EnvironmentVariableKeyProvider", func() {
			var (
				kp ear.EnvironmentVariableKeyProvider
			)

			it("does not modify if it does not detect", func() {
				Expect(kp.Detect(ctx, &result)).To(Succeed())

				Expect(result.Pass).To(BeFalse())
				Expect(result.Plans).To(HaveLen(0))
			})

			context("BP_EAR_KEY", func() {
				it.Before(func() {
					Expect(os.Setenv("BP_EAR_KEY", "E48F0660412A993E62FB11CA086C2D353C95359AD3A3480E778FBA43DB694E60")).To(Succeed())
				})

				it.After(func() {
					Expect(os.Unsetenv("BP_EAR_KEY")).To(Succeed())
				})

				it("modifies result if BP_EAR_KEY exists", func() {
					Expect(kp.Detect(ctx, &result)).To(Succeed())

					Expect(result.Pass).To(BeTrue())
					Expect(result.Plans).To(HaveLen(1))
					Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
						Provides: []libcnb.BuildPlanProvide{
							{Name: "encrypt-at-rest"},
						},
						Requires: []libcnb.BuildPlanRequire{
							{Name: "encrypt-at-rest", Metadata: map[string]interface{}{"type": "environment-variable"}},
						},
					}))
				})

			})

		})
	})

}
