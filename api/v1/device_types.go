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

// "ios", "macos", or unset.
type DeviceType string

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// DeviceSpec defines the desired state of Device
type DeviceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	NetworkRef NetworkReference `json:"networkRef,omitempty"`
	Type       DeviceType       `json:"type,omitempty"`
	IPs        []string         `json:"ips,omitempty"`
	// Empty string means overwrite default value in server config with empty, while nil
	// means to use default value in server config.
	DNS *string `json:"dns,omitempty"`
	// Empty string means overwrite default value in server config with empty, while nil
	// means to use default value in server config.
	ServerEndpoint *string `json:"serverEndpoint,omitempty"`
}

// DeviceStatus defines the observed state of Device
type DeviceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Device is the Schema for the devices API
type Device struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DeviceSpec   `json:"spec,omitempty"`
	Status DeviceStatus `json:"status,omitempty"`

	// Secret Reference to store Device private key that is not supposed to be read by
	// other resources.
	SecretRef corev1.SecretReference `json:"secretRef,omitempty"`
	// Secret Reference to store Device peer preshared key to share with Network.
	SecretPSKRef corev1.SecretReference `json:"secretPSKRef,omitempty"`
	// Secret Reference to store Device configuration content to download for users.
	SecretConfigRef corev1.SecretReference `json:"secretConfigRef,omitempty"`

	// Base64 encoded device WireGuard interface public key.
	// Automatically set after the reconciliation.
	PublicKey string `json:"publicKey,omitempty"`
}

//+kubebuilder:object:root=true

// DeviceList contains a list of Device
type DeviceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Device `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Device{}, &DeviceList{})
}
