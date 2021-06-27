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
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	log := log.FromContext(ctx)

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

	res, err = r.reconcileSecret(ctx, req, dev, net)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	log.Info("Nothing to do", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
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

// 2. Reconcile Device Secret reference.
func (r *DeviceReconciler) reconcileSecretReference(ctx context.Context, req ctrl.Request, dev *starv1.Device) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if dev.SecretRef == (corev1.SecretReference{}) {
		log.Info("Device SecretRef not set. Generating and setting", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
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
			log.Error(err, "Failed to patch Secret reference")
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

// 4. Reconcile Secret for general purpose.
func (r *DeviceReconciler) reconcileSecret(ctx context.Context, req ctrl.Request, dev *starv1.Device, net *starv1.Network) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	ns := dev.SecretRef.Namespace
	if ns == "" {
		ns = dev.Namespace
	}

	sec := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: dev.SecretRef.Name, Namespace: ns}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil
		var spkb []byte
		spkb, err = base64.StdEncoding.DecodeString(net.Status.ServerPublicKey)
		if err != nil {
			log.Error(err, "Failed to decode public key from network status as base64")
			res = &ctrl.Result{}
			return
		} else if len(spkb) == 0 {
			log.Info("Not found public key in Network status. Requeue and wait for the conditions to be met", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
			res = &ctrl.Result{Requeue: true}
			return
		} else if len(spkb) != wireguard.PublicKeySize {
			err = fmt.Errorf("length of public key is %d while expecting %d", len(spkb), wireguard.PublicKeySize)
			log.Error(err, "Failed to get public key from network status")
			res = &ctrl.Result{}
			return
		}

		var spk wireguard.PublicKey
		copy(spk[:], spkb)

		var ppk wireguard.PrivateKey
		ppk, err = wireguard.NewPrivateKey()
		if err != nil {
			res = &ctrl.Result{}
			return
		}

		var sspk wireguard.PrivateKey
		sspk, err = wireguard.NewPrivateKey()
		if err != nil {
			res = &ctrl.Result{}
			return
		}

		var ss wireguard.PresharedKey
		ss, err = sspk.SharedSecret(sspk.PublicKey())
		if err != nil {
			res = &ctrl.Result{}
			return
		}

		var sec *corev1.Secret
		sec, err = r.secret(dev, *net, spk, ppk, ss)
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)

		err = r.Create(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	} else if err != nil {
		log.Error(err, "Failed to get Secret")
		res = &ctrl.Result{}
		return
	}

	// Private key
	devPrivate := sec.Data[devPrivateKeySecretKey]
	var pk wireguard.PrivateKey
	if len(devPrivate) == 0 {
		log.Info("Skipped parsing private key because not present", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
	} else if len(devPrivate) != wireguard.PrivateKeySize {
		err = fmt.Errorf("length of private key in Secret is %d while expecting length %d", len(devPrivate), wireguard.PrivateKeySize)
		log.Error(err, "Failed to get private key", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		res = &ctrl.Result{}
		return
	} else {
		copy(pk[:], devPrivate)
	}

	// Preshared key
	devPreshared := sec.Data[devPresharedKeySecretKey]
	var psk wireguard.PrivateKey
	if len(devPreshared) == 0 {
		log.Info("Skipped parsing preshared key because not present", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		res = &ctrl.Result{Requeue: true}
		return
	} else if len(devPreshared) != wireguard.PresharedKeySize {
		err = fmt.Errorf("length of preshared key in Secret is %d while expecting length %d", len(devPreshared), wireguard.PresharedKeySize)
		log.Error(err, "Failed to get preshared key", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		res = &ctrl.Result{}
		return
	} else {
		copy(psk[:], devPreshared)
	}
	return
}

// 4.a. Generate Secret.
func (r *DeviceReconciler) secret(dev *starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (*corev1.Secret, error) {
	ls := r.labels(dev.Name)

	devConf, err := deviceConf(*dev, net, srvPub, pk, psk)
	if err != nil {
		return nil, err
	}

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dev.SecretRef.Name,
			Namespace: dev.Namespace,
			Labels:    ls,
		},
		Data: map[string][]byte{
			devPrivateKeySecretKey:   pk[:],
			devPresharedKeySecretKey: psk[:],
			devConfSecretKey:         []byte(devConf),
		},
	}

	ctrl.SetControllerReference(dev, sec, r.Scheme)
	return sec, nil
}

// 4.a.a. Generate Secret.
func deviceConf(dev starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (string, error) {
	var as wireguard.IPAddresses
	for i, ip := range dev.Spec.IPs {
		a, err := wireguard.ParseIPAddress(ip)
		if err != nil {
			return "", fmt.Errorf("error in %d-th server ip %q: %s", i+1, ip, err)
		}
		as = append(as, a)
	}

	e := dev.Spec.ServerEndpoint
	if e == "" {
		e = net.Spec.DefaultServerEndpoint
	}
	se, err := wireguard.ParseExternalEndpoint(e)
	if err != nil {
		return "", fmt.Errorf("parse error in server external endpoint %q: %s", e, err)
	}

	return wireguard.BuildDevConf(wireguard.DevConf{
		DevicePrivateKey: pk,
		DeviceAddress:    as,
		ServerPublicKey:  srvPub,
		PeerPresharedKey: psk,
		AllowedIPs:       allIPRanges,
		ServerEndpoint:   se,
	})
}

// Common labels for resources managed by Device.
func (DeviceReconciler) labels(name string) map[string]string {
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
