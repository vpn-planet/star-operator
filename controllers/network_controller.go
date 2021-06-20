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
	"bytes"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	starvpnv1 "github.com/vpn-planet/star-vpn-operator/api/v1"
	"github.com/vpn-planet/star-vpn-operator/internal/wireguard"
)

const (
	wg0ConfKey    = "wg0.conf"
	srvPrivateKey = "server-private-key"
)

var (
	initialCommand = []string{
		"sh",
		"-ce",
		strings.Join([]string{
			"sysctl -w net.ipv4.ip_forward=1",
			"sysctl -w net.ipv6.conf.all.forwarding=1",
			"wg-quick up wg0",
			"while true; do sleep infinity; done",
		}, "\n"),
	}
)

// NetworkReconciler reconciles a Network object
type NetworkReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=star-vpn.vpn-planet,resources=networks,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=star-vpn.vpn-planet,resources=networks/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=star-vpn.vpn-planet,resources=networks/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Network object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	network := &starvpnv1.Network{}
	err := r.Get(ctx, req.NamespacedName, network)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Network resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Network")
		return ctrl.Result{}, err
	}

	sec := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: secretName(network.Name), Namespace: network.Namespace}, sec)
	if err != nil && errors.IsNotFound(err) {
		sec, err := r.secretForNetwork(network)
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			return ctrl.Result{}, err
		}

		log.Info("Creating a new Secret", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)

		err = r.Create(ctx, sec)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			return ctrl.Result{}, err
		}

		// Secret created successfully - return and requeue
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		log.Error(err, "Failed to get Deployment")
		return ctrl.Result{}, err
	}

	srvPrivate := sec.Data[srvPrivateKey]
	wg0Conf := sec.Data[wg0ConfKey]
	wg0ConfDesired, err := serverConf(string(srvPrivate), *network)
	if err != nil {
		log.Error(err, "Failed to construct a server config file content")
		return ctrl.Result{}, err
	}

	if !bytes.Equal(wg0Conf, []byte(wg0ConfDesired)) {
		sec.Data[wg0ConfKey] = wg0Conf
		r.Update(ctx, sec)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	dep := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: deploymentName(network.Name), Namespace: network.Namespace}, dep)

	if err != nil && errors.IsNotFound(err) {
		dep := r.deploymentForNetwork(network)
		log.Info("Creating a new Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
		err = r.Create(ctx, dep)
		if err != nil {
			log.Error(err, "Failed to create new Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
			return ctrl.Result{}, err
		}
		// Deployment created successfully - return and requeue
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		log.Error(err, "Failed to get Deployment")
		return ctrl.Result{}, err
	}

	if *dep.Spec.Replicas != *network.Spec.Replicas {
		replicas := *network.Spec.Replicas
		dep.Spec.Replicas = &replicas
		err = r.Update(ctx, dep)
		if err != nil {
			log.Error(err, "Failed to update Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	devices := getDevices()
	if devices != network.Status.Devices {
		network.Status.Devices = devices
		err := r.Status().Update(ctx, network)
		if err != nil {
			log.Error(err, "Failed to update Memcached status")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *NetworkReconciler) secretForNetwork(m *starvpnv1.Network) (*corev1.Secret, error) {
	p, err := wireguard.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	srvPriv := p.ToHex()
	srvConf, err := serverConf(srvPriv, *m)
	if err != nil {
		return nil, err
	}

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName(m.Name),
			Namespace: m.Namespace,
		},
		Data: map[string][]byte{
			srvPrivateKey: []byte(srvPriv),
			wg0ConfKey:    []byte(srvConf),
		},
	}

	ctrl.SetControllerReference(m, sec, r.Scheme)
	return sec, nil
}

func (r *NetworkReconciler) deploymentForNetwork(m *starvpnv1.Network) *appsv1.Deployment {
	ls := labelsForNetwork(m.Name)
	replicas := *m.Spec.Replicas
	privileged := true

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName(m.Name),
			Namespace: m.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: ls,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Image: m.Spec.WireguardImage,
						Name:  "star-vpn-server",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
						},
						Env:     m.Spec.Env,
						Command: initialCommand,
						Ports: []corev1.ContainerPort{{
							ContainerPort: 51820,
							Name:          "wireguard",
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: secretName(m.Name),
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								Items: []corev1.KeyToPath{{
									Key:  wg0ConfKey,
									Path: "/etc/wireguard/wg0.conf",
								}},
							},
						},
					}},
				},
			},
		},
	}

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

func secretName(n string) string {
	return n + "-server-config"
}

func deploymentName(n string) string {
	return n + "-server"
}

func serverConf(priv string, network starvpnv1.Network) (string, error) {
	var pk wireguard.PrivateKey
	if priv == "" {
		pk, _ = wireguard.NewPrivateKey()
	} else {
		err := pk.FromHex(priv)
		if err != nil {
			return "", err
		}
	}

	var address wireguard.IPAddresses

	return wireguard.BuildSrvConf(wireguard.ServerConf{
		IPv4Enabled:      network.Spec.IPv4Enabled,
		IPv6Enabled:      network.Spec.IPv6Enabled,
		ServerPrivateKey: pk,
		ServerAddress:    address,
		Devices:          []wireguard.ServerConfDevice{},
	})
}

func labelsForNetwork(name string) map[string]string {
	return map[string]string{"star-vpn.vpn-planet/app": "network", "star-vpn.vpn-planet/name": name}
}

func getDevices() int32 {
	// TODO
	return 3
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&starvpnv1.Network{}).
		Complete(r)
}
