/*
 * Copyright © 2019 Banzai Cloud
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fluentbit

import (
	"github.com/banzaicloud/logging-operator/pkg/k8sutil"
	"github.com/banzaicloud/logging-operator/pkg/resources/templates"
	"github.com/banzaicloud/logging-operator/pkg/util"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (r *Reconciler) clusterPodSecurityPolicy() (runtime.Object, k8sutil.DesiredState) {
	if r.Logging.Spec.FluentbitSpec.Security.PodSecurityPolicyCreate {

		return &policyv1beta1.PodSecurityPolicy{
			ObjectMeta: templates.FluentbitObjectMeta(
				r.Logging.QualifiedName(fluentbitPodSecurityPolicyName),
				util.MergeLabels(r.Logging.Labels, r.getFluentBitLabels()),
				r.Logging),
			Spec: policyv1beta1.PodSecurityPolicySpec{
				Privileged:               false,
				DefaultAddCapabilities:   nil,
				RequiredDropCapabilities: nil,
				AllowedCapabilities:      nil,
				Volumes: []policyv1beta1.FSType{
					"configMap",
					"emptyDir",
					"secret",
					"hostPath"},
				HostNetwork: false,
				HostPorts:   nil,
				HostPID:     false,
				HostIPC:     false,
				SELinux: policyv1beta1.SELinuxStrategyOptions{
					Rule:           policyv1beta1.SELinuxStrategyRunAsAny,
					SELinuxOptions: nil,
				},
				RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
					Rule:   policyv1beta1.RunAsUserStrategyMustRunAs,
					Ranges: []policyv1beta1.IDRange{{Min: 1, Max: 65535}}},
				RunAsGroup: nil,
				SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
					Rule:   policyv1beta1.SupplementalGroupsStrategyMustRunAs,
					Ranges: []policyv1beta1.IDRange{{Min: 1, Max: 65535}},
				},
				FSGroup: policyv1beta1.FSGroupStrategyOptions{
					Rule:   policyv1beta1.FSGroupStrategyMustRunAs,
					Ranges: []policyv1beta1.IDRange{{Min: 1, Max: 65535}},
				},
				ReadOnlyRootFilesystem:          true,
				DefaultAllowPrivilegeEscalation: nil,
				AllowPrivilegeEscalation:        util.BoolPointer(false),
				AllowedHostPaths: []policyv1beta1.AllowedHostPath{{
					PathPrefix: "/var/lib/docker/containers",
					ReadOnly:   true,
				}, {
					PathPrefix: "/var/log",
					ReadOnly:   true,
				}},
				AllowedFlexVolumes:    nil,
				AllowedCSIDrivers:     nil,
				AllowedUnsafeSysctls:  nil,
				ForbiddenSysctls:      nil,
				AllowedProcMountTypes: nil,
			},
		}, k8sutil.StatePresent

	}
	return nil, k8sutil.StatePresent
}
