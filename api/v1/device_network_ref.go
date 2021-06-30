package v1

import (
	"k8s.io/apimachinery/pkg/types"
)

func (d Device) NetworkNamespacedName() types.NamespacedName {
	ns := d.Spec.NetworkRef.Namespace
	if ns == "" {
		ns = d.Namespace
	}

	return types.NamespacedName{Name: d.Spec.NetworkRef.Name, Namespace: ns}
}
