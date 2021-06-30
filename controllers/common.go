package controllers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	starv1 "github.com/vpn-planet/star-operator/api/v1"
	"github.com/vpn-planet/star-operator/internal/wireguard"
)

// Reconcile Devices that belongs to specific Network.
func reconcileNetworkDevices(c client.Client, ctx context.Context, req ctrl.Request, net starv1.Network) (devs []starv1.Device, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	dl := &starv1.DeviceList{}
	err = c.List(ctx, dl)
	if err != nil {
		log.Error(err, "Failed to list all Devices in any namespace")
		res = &ctrl.Result{}
		return
	}

	for _, item := range dl.Items {
		ns := item.Namespace
		if item.Spec.NetworkRef.Namespace != "" {
			ns = item.Spec.NetworkRef.Namespace
		}
		if item.Spec.NetworkRef.Name == net.Name && ns == net.Namespace {
			devs = append(devs, item)
		}
	}
	return
}

// Reconcile Secret for general purpose.
func reconcileDeviceSecret(c client.Client, ctx context.Context, req ctrl.Request, dev starv1.Device, net starv1.Network) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	// Get server public key from Network Status
	var spkb []byte
	spkb, err = base64.StdEncoding.DecodeString(net.Status.ServerPublicKey)
	if err != nil {
		log.Error(err, "Failed to decode public key from network status as base64")
		res = &ctrl.Result{}
		return
	} else if len(spkb) == 0 {
		log.Info("Not found public key in Network Status. Requeue and wait for the conditions to be met", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
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

	ns := dev.SecretRef.Namespace
	if ns == "" {
		ns = dev.Namespace
	}

	sec := &corev1.Secret{}
	err = c.Get(ctx, types.NamespacedName{Name: dev.SecretRef.Name, Namespace: ns}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil

		var ppk wireguard.PrivateKey
		ppk, err = wireguard.NewPrivateKey()
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			res = &ctrl.Result{}
			return
		}

		var sspk wireguard.PrivateKey
		sspk, err = wireguard.NewPrivateKey()
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			res = &ctrl.Result{}
			return
		}

		var ss wireguard.PresharedKey
		ss, err = sspk.SharedSecret(sspk.PublicKey())
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			res = &ctrl.Result{}
			return
		}

		var sec *corev1.Secret
		sec, err = deviceSecret(c, dev, net, spk, ppk, ss)
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)

		err = c.Create(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{RequeueAfter: 5 * time.Second}
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
	var psk wireguard.PresharedKey
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

	// Check whether the Secret data is desired
	var ds string
	ds, err = deviceConf(dev, net, spk, pk, psk)
	desired := []byte(ds)
	if err != nil {
		log.Error(err, "Failed to get desired Device WireGuard Quick Config")
		res = &ctrl.Result{}
		return
	}
	conf := sec.Data[devConfSecretKey]
	if !bytes.Equal(conf, desired) {
		log.Info("Updating Secret Device Config", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		sec.Data[devConfSecretKey] = desired
		err = c.Update(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to patch Secret Device Config", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{RequeueAfter: time.Second}
		return
	}

	return
}

// Generate Device Secret.
func deviceSecret(c client.Client, dev starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (*corev1.Secret, error) {
	ls := labelsForDevice(dev.Name)

	devConf, err := deviceConf(dev, net, srvPub, pk, psk)
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

	ctrl.SetControllerReference(&dev, sec, c.Scheme())
	return sec, nil
}

// Generate Device Config file content.
func deviceConf(dev starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (string, error) {
	var as wireguard.IPAddresses
	for i, ip := range dev.Spec.IPs {
		a, err := wireguard.ParseIPAddress(ip)
		if err != nil {
			return "", fmt.Errorf("error in %d-th server ip %q: %s", i+1, ip, err)
		}
		as = append(as, a)
	}

	e := net.Spec.DefaultServerEndpoint
	if dev.Spec.ServerEndpoint != nil {
		e = *dev.Spec.ServerEndpoint
	}
	se, err := wireguard.ParseExternalEndpoint(e)
	if err != nil {
		return "", fmt.Errorf("parse error in server external endpoint %q: %s", e, err)
	}

	dns := net.Spec.DefaultDeviceDNS
	if dev.Spec.DNS != nil {
		dns = *dev.Spec.DNS
	}

	return wireguard.BuildDevConf(wireguard.DevConf{
		DevicePrivateKey: pk,
		DeviceAddress:    as,
		DNS:              dns,
		ServerPublicKey:  srvPub,
		PeerPresharedKey: psk,
		AllowedIPs:       allIPRanges,
		ServerEndpoint:   se,
	})
}

// Reconcile Network Status Devices.
func reconcileNetworkStatusDevices(c client.Client, ctx context.Context, req ctrl.Request, net starv1.Network, devs []starv1.Device) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	desired := int32(len(devs))
	if net.Status.Devices != desired {
		log.Info("Patching Network Status devices", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(net.GroupVersionKind())
		patch.SetNamespace(net.Namespace)
		patch.SetName(net.Name)
		patch.UnstructuredContent()["status"] = map[string]interface{}{
			"devices": desired,
		}
		err = c.Status().Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "network_status_server_devices",
		})
		if err != nil {
			log.Error(err, "Failed to patch Network Status devices", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}
