/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetworkSpec defines the desired state of Network
type NetworkSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Cidr block used in VPN network
	Cidrs []string `json:"cidrs,omitempty"`
	// Star VPN server IP addresses that is in cidr block
	ServerIPs []string `json:"serverIPs,omitempty"`

	// Defaults to 1.
	// More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#what-is-a-replicationcontroller
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// WireGuard installed image source for server container
	// If omitted, docker.io/vpnplanet/wireguard:latest will be used
	// +optional
	WireguardImage string `json:"wireguardImage,omitempty"`

	// List of environment variables to set in the container.
	// Cannot be updated.
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	Env []corev1.EnvVar `json:"env,omitempty" patchStrategy:"merge" patchMergeKey:"name"`

	IPv4Enabled bool `json:"ipv4Enabled,omitempty"`
	IPv6Enabled bool `json:"ipv6Enabled,omitempty"`

	// Image pull policy.
	// One of Always, Never, IfNotPresent.
	// Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
	// Cannot be updated.
	// More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	DefaultDeviceDNS      string `json:"defaultDeviceDNS,omitempty"`
	DefaultServerEndpoint string `json:"defaultServerEndpoint,omitempty"`

	// Organization name for mobileconfig PayloadOrganization
	PayloadOrganization *string `json:"payloadOrganization,omitempty"`
	// Name for mobileconfig PayloadDisplayName, the name of
	// the configuration profile, visible when installing the profile
	PayloadDisplayName *string `json:"payloadDisplayName,omitempty"`
	// Name in mobileconfig UserDefinedName, the name of the WireGuard tunnel.
	// This name shall be used to represent the tunnel in the WireGuard app, and in the System UI for VPNs (Settings > VPN on iOS, System Preferences > Network on macOS).
	UserDefinedName *string `json:"userDefinedName,omitempty"`
}

// NetworkStatus defines the observed state of Network
type NetworkStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Devices int32 `json:"devices,omitempty"`
}

//+kubebuilder:object:root=true

// Network is the Schema for the networks API
//+kubebuilder:subresource:status
type Network struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkSpec   `json:"spec,omitempty"`
	Status NetworkStatus `json:"status,omitempty"`

	SecretRef       corev1.SecretReference `json:"secretRef,omitempty"`
	ConfigSecretRef LocalSecretReference   `json:"configSecretRef,omitempty"`

	// Base64 encoded server WireGuard interface public key.
	// Automatically set after the reconciliation.
	ServerPublicKey string `json:"serverPublicKey,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkList contains a list of Network
type NetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Network `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Network{}, &NetworkList{})
}
