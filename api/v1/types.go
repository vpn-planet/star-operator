package v1

// LocalSecretReference contains enough information to let you locate the
// referenced secret inside the same namespace.
// Inspired by corev1.LocalObjectReference and corev1.SecretReference
type LocalSecretReference struct {
	// Name of the referent.
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
}
