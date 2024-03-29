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

package controllers

import (
	"encoding/base64"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	starv1 "github.com/vpn-planet/star-operator/api/v1"
	"github.com/vpn-planet/star-operator/internal/wireguard"

	"k8s.io/apiserver/pkg/storage/names"
)

const (
	devPrivateKeySecretKey   = "device-private-key"
	devPresharedKeySecretKey = "device-preshared-key"
	devConfSecretKey         = "device-config"
)

var (
	allIPRanges = wireguard.IPRanges{
		wireguard.IPRange{
			IP:  net.IPv4(0, 0, 0, 0),
			Pre: 0,
		},
		wireguard.IPRange{
			IP:  net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Pre: 0,
		},
	}
)

// DeviceReconciler reconciles a Device object
type DeviceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=star.vpn-planet,resources=devices,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=star.vpn-planet,resources=devices/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=star.vpn-planet,resources=devices/finalizers,verbs=update
//+kubebuilder:rbac:groups=star.vpn-planet,resources=networks,verbs=get;list;watch
//+kubebuilder:rbac:groups=star.vpn-planet,resources=networks/status,verbs=get
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// NOTE(user): Modify the Reconcile function to compare the state specified by
// the Device object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *DeviceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	dev, res, err := r.reconcileDevice(ctx, req)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileSecretReference(ctx, req, dev)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcilePSKSecretReference(ctx, req, dev)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileConfigSecretReference(ctx, req, dev)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	var pk wireguard.PrivateKey
	pk, res, err = reconcileDeviceSecret(r.Client, ctx, req, *dev, true)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	var psk wireguard.PresharedKey
	psk, res, err = reconcileDeviceSecretPSK(r.Client, ctx, req, *dev, true)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcilePubkey(ctx, req, dev, pk)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	var net *starv1.Network
	net, res, err = r.reconcileNetwork(ctx, req, dev)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	var srvPub wireguard.PublicKey
	srvPub, res, err = reconcileNetworkPublicKey(ctx, req, *net)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileDeviceSecretConfig(ctx, req, *dev, *net, srvPub, pk, psk)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	return ctrl.Result{}, nil
}

// 1. Reconcile Device.
func (r *DeviceReconciler) reconcileDevice(ctx context.Context, req ctrl.Request) (dev *starv1.Device, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	dev = &starv1.Device{}
	err = r.Get(ctx, req.NamespacedName, dev)
	if err != nil {
		if errors.IsNotFound(err) {
			err = nil
			log.Info("Device resource not found. Ignoring since object must be deleted")
			res = &ctrl.Result{}
			return
		}
		log.Error(err, "Failed to get Device")
		res = &ctrl.Result{}
		return
	}
	return
}

// 2. Reconcile Device Secret Reference.
func (r *DeviceReconciler) reconcileSecretReference(ctx context.Context, req ctrl.Request, dev *starv1.Device) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if dev.SecretRef == (corev1.SecretReference{}) {
		log.Info("Device SecretRef not set. Patching Device SecretRef", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(dev.GroupVersionKind())
		patch.SetNamespace(dev.Namespace)
		patch.SetName(dev.Name)
		patch.UnstructuredContent()["secretRef"] = map[string]interface{}{
			"name": genDeviceSecretName(dev.Name),
		}
		force := true
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "star.vpn-planet/reconcile/device/secret-reference",
			Force:        &force,
		})
		if err != nil {
			log.Error(err, "Failed to patch SecretRef", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}

// 2.a. Generate Secret name.
func genDeviceSecretName(n string) string {
	return names.SimpleNameGenerator.GenerateName(n + "-device-")
}

// 3. Reconcile Device Secret Reference for PSK.
func (r *DeviceReconciler) reconcilePSKSecretReference(ctx context.Context, req ctrl.Request, dev *starv1.Device) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if dev.PSKSecretRef == (corev1.SecretReference{}) {
		log.Info("Device PSKSecretRef not set. Patching Device PSKSecretRef", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(dev.GroupVersionKind())
		patch.SetNamespace(dev.Namespace)
		patch.SetName(dev.Name)
		patch.UnstructuredContent()["pskSecretRef"] = map[string]interface{}{
			"name": genDeviceSecretPSKName(dev.Name),
		}
		force := true
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "star.vpn-planet/reconcile/device/secret-psk-reference",
			Force:        &force,
		})
		if err != nil {
			log.Error(err, "Failed to patch PSKSecretRef", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}

// 3.a. Generate Secret name for preshared key.
func genDeviceSecretPSKName(n string) string {
	return names.SimpleNameGenerator.GenerateName(n + "-device-psk-")
}

// 4. Reconcile Device Secret Reference for Config content.
func (r *DeviceReconciler) reconcileConfigSecretReference(ctx context.Context, req ctrl.Request, dev *starv1.Device) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if dev.ConfigSecretRef == (corev1.SecretReference{}) {
		log.Info("Device ConfigSecretRef not set. Patching Device ConfigSecretRef", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(dev.GroupVersionKind())
		patch.SetNamespace(dev.Namespace)
		patch.SetName(dev.Name)
		patch.UnstructuredContent()["configSecretRef"] = map[string]interface{}{
			"name": genDeviceSecretConfigName(dev.Name),
		}
		force := true
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "secret_config_ref",
			Force:        &force,
		})
		if err != nil {
			log.Error(err, "Failed to patch ConfigSecretRef", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}

// 4.a. Generate Secret name for Device WireGuard config file content.
func genDeviceSecretConfigName(n string) string {
	return names.SimpleNameGenerator.GenerateName(n + "-device-config-")
}

// 5. Reconcile Device public key.
func (r *DeviceReconciler) reconcilePubkey(ctx context.Context, req ctrl.Request, dev *starv1.Device, pk wireguard.PrivateKey) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if len(pk) == 0 {
		log.Info("Private key is not set. Skipped checking Device public key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		return
	}

	pubkey := pk.PublicKey()
	desired := base64.StdEncoding.EncodeToString(pubkey[:])

	if dev.PublicKey != desired {
		log.Info("Patching Device public key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(dev.GroupVersionKind())
		patch.SetNamespace(dev.Namespace)
		patch.SetName(dev.Name)
		patch.UnstructuredContent()["publicKey"] = desired
		force := true
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "public_key",
			Force:        &force,
		})
		if err != nil {
			log.Error(err, "Failed to patch Device public key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}

// 6. Reconcile Network.
func (r *DeviceReconciler) reconcileNetwork(ctx context.Context, req ctrl.Request, dev *starv1.Device) (net *starv1.Network, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	net = &starv1.Network{}

	err = r.Get(ctx, dev.NetworkNamespacedName(), net)
	if err != nil {
		log.Error(err, "Failed to get Network", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}

// 7. Reconcile Secret for Device WireGuard config file content.
func (r *DeviceReconciler) reconcileDeviceSecretConfig(ctx context.Context, req ctrl.Request, dev starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if len(srvPub) == 0 {
		log.Info("Not found public key in Network. Skipped the reconciliation of Device Secret for Device WireGuard config file content", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		return
	}

	res, err = reconcileDeviceSecretConfig(r.Client, ctx, req, dev, net, srvPub, pk, psk)
	if res != nil || err != nil {
		return
	}
	return
}

// Common labels for resources managed by Device.
func labelsForDevice(name string) map[string]string {
	return map[string]string{
		"vpn-planet":      "true",
		"star.vpn-planet": "true",
		"app":             "device",
		"name":            name,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *DeviceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&starv1.Device{}).
		Complete(r)
}
