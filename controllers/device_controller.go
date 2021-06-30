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
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

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

	var net *starv1.Network
	net, res, err = r.reconcileNetwork(ctx, req, dev)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = commonNetDevReconcile(r.Client, ctx, req, *net)
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
			res, err = commonNetDevAllReconcile(r.Client, ctx, req)
			if res == nil {
				if err != nil {
					panic(errReturnWithoutResult)
				}
				log.Info("Device resource not found and all Network up to date. Ignoring since object must be deleted")
				res = &ctrl.Result{}
			}
			return
		}
		log.Error(err, "Failed to get Device")
		res = &ctrl.Result{}
		return
	}
	return
}

// 2. Reconcile Device Secret reference.
func (r *DeviceReconciler) reconcileSecretReference(ctx context.Context, req ctrl.Request, dev *starv1.Device) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if dev.SecretRef == (corev1.SecretReference{}) {
		log.Info("Device Secret Reference not set. Patching Device Secret Reference", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(dev.GroupVersionKind())
		patch.SetNamespace(dev.Namespace)
		patch.SetName(dev.Name)
		patch.UnstructuredContent()["secretRef"] = map[string]interface{}{
			"name": genDeviceSecretName(dev.Name),
		}
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "secret_ref",
		})
		if err != nil {
			log.Error(err, "Failed to patch Secret Reference", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
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

// 3. Reconcile Network.
func (r *DeviceReconciler) reconcileNetwork(ctx context.Context, req ctrl.Request, dev *starv1.Device) (net *starv1.Network, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	net = &starv1.Network{}

	ns := dev.Spec.NetworkRef.Namespace
	if ns == "" {
		ns = dev.Namespace
	}

	err = r.Get(ctx, types.NamespacedName{Name: dev.Spec.NetworkRef.Name, Namespace: ns}, net)
	if err != nil {
		log.Error(err, "Failed to get Network")
		res = &ctrl.Result{RequeueAfter: 5 * time.Second}
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
