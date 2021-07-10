package controllers

import (
	"bytes"
	"encoding/base64"
	"fmt"

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
		log.Error(err, "Failed to list all Devices in any namespace", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
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

// Reconcile Device public keys.
func reconcileDevicePublicKeys(c client.Client, ctx context.Context, req ctrl.Request, devs []starv1.Device) (devPubs *[]wireguard.PublicKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	var pubs []wireguard.PublicKey
	for _, dev := range devs {
		var pub wireguard.PublicKey
		pub, res, err = reconcileDevicePublicKey(ctx, req, dev)
		if res != nil || err != nil {
			return
		}
		if len(pub) == 0 {
			log.Info("Not found Device public key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			return
		}
		pubs = append(pubs, pub)
	}
	devPubs = &pubs
	return
}

// Reconcile Device private keys.
func reconcileDevicePrivateKeys(c client.Client, ctx context.Context, req ctrl.Request, devs []starv1.Device) (devPKs *[]wireguard.PrivateKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	var pks []wireguard.PrivateKey
	for _, dev := range devs {
		var pk wireguard.PrivateKey
		pk, res, err = reconcileDeviceSecret(c, ctx, req, dev, false)
		if res != nil || err != nil {
			return
		}
		if len(pk) == 0 {
			log.Info("Not found Device private key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			return
		}
		pks = append(pks, pk)
	}
	devPKs = &pks
	return
}

// Reconcile Device preshared keys.
func reconcileDevicePresharedKeys(c client.Client, ctx context.Context, req ctrl.Request, devs []starv1.Device) (devPSKs *[]wireguard.PresharedKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	var psks []wireguard.PresharedKey
	for _, dev := range devs {
		var pk wireguard.PresharedKey
		pk, res, err = reconcileDeviceSecretPSK(c, ctx, req, dev, false)
		if res != nil || err != nil {
			return
		}
		if len(pk) == 0 {
			log.Info("Not found Device preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			return
		}
		psks = append(psks, pk)
	}
	devPSKs = &psks
	return
}

// Reconcile Network public key.
func reconcileNetworkPublicKey(ctx context.Context, req ctrl.Request, net starv1.Network) (srvPub wireguard.PublicKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	// Get server public key from Network
	var spkb []byte
	spkb, err = base64.StdEncoding.DecodeString(net.ServerPublicKey)
	if err != nil {
		log.Error(err, "Failed to decode public key from Network as base64", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		res = &ctrl.Result{}
		return
	} else if len(spkb) == 0 {
		log.Info("Not found public key in Network. Skipped the reconciliation of Network public key", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		return
	} else if len(spkb) != wireguard.PublicKeySize {
		err = fmt.Errorf("length of public key is %d while expecting %d", len(spkb), wireguard.PublicKeySize)
		log.Error(err, "Failed to get public key from Network", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		res = &ctrl.Result{}
		return
	}
	copy(srvPub[:], spkb)
	return
}

// Reconcile Device public key.
func reconcileDevicePublicKey(ctx context.Context, req ctrl.Request, dev starv1.Device) (srvPub wireguard.PublicKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	// Get server public key from Device Status
	var spkb []byte
	spkb, err = base64.StdEncoding.DecodeString(dev.PublicKey)
	if err != nil {
		log.Error(err, "Failed to decode public key from Device Status as base64", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{}
		return
	} else if len(spkb) == 0 {
		log.Info("Not found public key in Device. Skipped the reconciliation of Device public key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{Requeue: true}
		return
	} else if len(spkb) != wireguard.PublicKeySize {
		err = fmt.Errorf("length of public key is %d while expecting %d", len(spkb), wireguard.PublicKeySize)
		log.Error(err, "Failed to get public key from Device Status", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{}
		return
	}
	copy(srvPub[:], spkb)
	return
}

// Reconcile Device Secret for general purpose.
func reconcileDeviceSecret(c client.Client, ctx context.Context, req ctrl.Request, dev starv1.Device, allowUpdates bool) (pk wireguard.PrivateKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	ns := dev.Namespace
	if dev.SecretRef.Namespace != "" {
		ns = dev.SecretRef.Namespace
	}

	sec := &corev1.Secret{}
	err = c.Get(ctx, types.NamespacedName{Name: dev.SecretRef.Name, Namespace: ns}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil

		if !allowUpdates {
			log.Error(err, "Device Secret for private key is not found and not allowed to update. Skipped the reconciliation of Device Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			return
		}

		pk, err = wireguard.NewPrivateKey()
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}

		var sec *corev1.Secret
		sec, err = deviceSecret(c, dev, pk)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)

		err = c.Create(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	} else if err != nil {
		log.Error(err, "Failed to get Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{}
		return
	}

	// Private key
	devPrivate := sec.Data[devPrivateKeySecretKey]
	if len(devPrivate) == 0 {
		log.Info("Skipped parsing private key because not present", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		return
	} else if len(devPrivate) != wireguard.PrivateKeySize {
		err = fmt.Errorf("length of private key in Secret is %d while expecting length %d", len(devPrivate), wireguard.PrivateKeySize)
		log.Error(err, "Failed to get private key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		res = &ctrl.Result{}
		return
	} else {
		copy(pk[:], devPrivate)
	}
	return
}

// Reconcile Device Secret for preshared key.
func reconcileDeviceSecretPSK(c client.Client, ctx context.Context, req ctrl.Request, dev starv1.Device, allowUpdates bool) (psk wireguard.PresharedKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	ns := dev.Namespace
	if dev.PSKSecretRef.Namespace != "" {
		ns = dev.PSKSecretRef.Namespace
	}

	sec := &corev1.Secret{}
	err = c.Get(ctx, types.NamespacedName{Name: dev.PSKSecretRef.Name, Namespace: ns}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil

		if !allowUpdates {
			log.Info("Device Secret for preshared key is not found and not allowed to update. Skipped the reconciliation of Device Secret", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			return
		}

		var sspk wireguard.PrivateKey
		sspk, err = wireguard.NewPrivateKey()
		if err != nil {
			log.Error(err, "Failed to create new Secret for preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}

		psk, err = sspk.SharedSecret(sspk.PublicKey())
		if err != nil {
			log.Error(err, "Failed to create new Secret for preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}

		var sec *corev1.Secret
		sec, err = deviceSecretPSK(c, dev, psk)
		if err != nil {
			log.Error(err, "Failed to create new Secret for preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret for preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)

		err = c.Create(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to create new Secret for preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	} else if err != nil {
		log.Error(err, "Failed to get Secret for preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{}
		return
	}

	// Preshared key
	devPreshared := sec.Data[devPresharedKeySecretKey]
	if len(devPreshared) == 0 {
		log.Info("Skipped parsing preshared key because not present", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		return
	} else if len(devPreshared) != wireguard.PresharedKeySize {
		err = fmt.Errorf("length of preshared key in Secret for preshared key is %d while expecting length %d", len(devPreshared), wireguard.PresharedKeySize)
		log.Error(err, "Failed to get preshared key", "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		res = &ctrl.Result{}
		return
	} else {
		copy(psk[:], devPreshared)
	}
	return
}

// Reconcile Device Secret for Device WireGuard config file content.
func reconcileDeviceSecretConfig(c client.Client, ctx context.Context, req ctrl.Request, dev starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if len(pk) == 0 {
		log.Info("Device private key is not present. Skipped checking Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		return
	}

	if len(psk) == 0 {
		log.Info("Device preshared key is not present. Skipped checking Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		return
	}

	ns := dev.Namespace
	if dev.ConfigSecretRef.Namespace != "" {
		ns = dev.ConfigSecretRef.Namespace
	}

	sec := &corev1.Secret{}
	err = c.Get(ctx, types.NamespacedName{Name: dev.ConfigSecretRef.Name, Namespace: ns}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil

		var sec *corev1.Secret
		sec, err = deviceSecretConfig(c, dev, net, srvPub, pk, psk)
		if err != nil {
			log.Error(err, "Failed to create new Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)

		err = c.Create(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to create new Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	} else if err != nil {
		log.Error(err, "Failed to get Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{}
		return
	}

	// Check whether the Secret data is desired
	var ds string
	ds, err = deviceConf(dev, net, srvPub, pk, psk)
	desired := []byte(ds)
	if err != nil {
		log.Error(err, "Failed to get desired Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name)
		res = &ctrl.Result{}
		return
	}
	conf := sec.Data[devConfSecretKey]
	if !bytes.Equal(conf, desired) {
		log.Info("Patching Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		log.Info("XXXXXXXXXXXXXXXXXX debug", "A", len(conf), "B", len(desired))
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(sec.GroupVersionKind())
		patch.SetNamespace(sec.Namespace)
		patch.SetName(sec.Name)
		patch.UnstructuredContent()["data"] = map[string]interface{}{
			devConfSecretKey: desired,
		}
		force := true
		err = c.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "star.vpn-planet/reconcile/device/secret-config",
			Force:        &force,
		})
		if err != nil {
			log.Error(err, "Failed to patch Secret for Device WireGuard config file content", "Network.Namespace", net.Namespace, "Network.Name", net.Name, "Device.Namespace", dev.Namespace, "Device.Name", dev.Name, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	return
}

// Generate Device Secret.
func deviceSecret(c client.Client, dev starv1.Device, pk wireguard.PrivateKey) (*corev1.Secret, error) {
	ls := labelsForDevice(dev.Name)

	ns := dev.Namespace
	if dev.SecretRef.Namespace != "" {
		ns = dev.SecretRef.Namespace
	}

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dev.SecretRef.Name,
			Namespace: ns,
			Labels:    ls,
		},
		Data: map[string][]byte{
			devPrivateKeySecretKey: pk[:],
		},
	}

	ctrl.SetControllerReference(&dev, sec, c.Scheme())
	return sec, nil
}

// Generate Device Secret for preshared key.
func deviceSecretPSK(c client.Client, dev starv1.Device, psk wireguard.PresharedKey) (*corev1.Secret, error) {
	ls := labelsForDevice(dev.Name)

	ns := dev.Namespace
	if dev.PSKSecretRef.Namespace != "" {
		ns = dev.PSKSecretRef.Namespace
	}

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dev.PSKSecretRef.Name,
			Namespace: ns,
			Labels:    ls,
		},
		Data: map[string][]byte{
			devPresharedKeySecretKey: psk[:],
		},
	}

	ctrl.SetControllerReference(&dev, sec, c.Scheme())
	return sec, nil
}

// Generate Device Secret for Device WireGuard config file content.
func deviceSecretConfig(c client.Client, dev starv1.Device, net starv1.Network, srvPub wireguard.PublicKey, pk wireguard.PrivateKey, psk wireguard.PresharedKey) (*corev1.Secret, error) {
	ls := labelsForDevice(dev.Name)

	devConf, err := deviceConf(dev, net, srvPub, pk, psk)
	if err != nil {
		return nil, err
	}

	ns := dev.Namespace
	if dev.ConfigSecretRef.Namespace != "" {
		ns = dev.ConfigSecretRef.Namespace
	}

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dev.ConfigSecretRef.Name,
			Namespace: ns,
			Labels:    ls,
		},
		Data: map[string][]byte{
			devConfSecretKey: []byte(devConf),
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
	devConf := wireguard.DevConf{
		DevicePrivateKey: pk,
		DeviceAddress:    as,
		DNS:              dns,
		ServerPublicKey:  srvPub,
		PeerPresharedKey: psk,
		AllowedIPs:       allIPRanges,
		ServerEndpoint:   se,
	}
	return wireguard.BuildDevConf(devConf)
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
		force := true
		err = c.Status().Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "star.vpn-planet/reconcile/network/status-server-devices",
			Force:        &force,
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
