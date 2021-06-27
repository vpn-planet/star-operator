package v1

// LocalSecretReference represents a Secret Reference inside the same
// namespace. It has enough information to retrieve secret in the
// same namespace.
type LocalSecretReference struct {
	// Name of the referent.
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
}

// LocalSecretReference represents a Network Reference. It has enough
// information to retrieve secret in any namespace.
type NetworkReference struct {
	// Name of the referent.
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// Namespace of the referent.
	// +optional
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}
