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
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
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
	wg0ConfKey             = "wg0.conf"
	srvPrivateKeySecretKey = "server-private-key"
	wgImgDefault           = "docker.io/vpnplanet/wireguard"
	wgPort                 = 51820
)

var (
	hangCommand = []string{
		"sh",
		"-c",
		strings.Join([]string{
			"while true; do sleep infinity; done",
		}, "\n"),
	}
	upCommand = []string{
		"sh",
		"-c",
		strings.Join([]string{
			"sysctl -w net.ipv4.ip_forward=1",
			"sysctl -w net.ipv6.conf.all.forwarding=1",
			"wg-quick up wg0",
		}, "\n"),
	}
	downCommand = []string{
		"sh",
		"-c",
		strings.Join([]string{
			"wg-quick down wg0",
		}, "\n"),
	}
)

// NetworkReconciler reconciles a Network object
type NetworkReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=star.vpn-planet,resources=networks,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=star.vpn-planet,resources=networks/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=star.vpn-planet,resources=networks/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete

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

	net, res, err := r.reconcileNetwork(ctx, req)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileSecretReference(ctx, req, net)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileSecretConfigReference(ctx, req, net)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	var pk wireguard.PrivateKey
	pk, res, err = r.reconcileSecret(ctx, req, net)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileSecretConfig(ctx, req, net, pk)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	var dep *appsv1.Deployment
	dep, res, err = r.reconcileDeployment(ctx, req, net)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	res, err = r.reconcileDeploymentReplicas(ctx, req, net, dep)
	if res != nil {
		return *res, err
	} else if err != nil {
		panic(errReturnWithoutResult)
	}

	// TODO: after devices
	devices := getDevices()
	if devices != net.Status.Devices {
		net.Status.Devices = devices
		err := r.Status().Update(ctx, net)
		if err != nil {
			log.Error(err, "Failed to update Network status")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// 1. Reconcile Network.
func (r *NetworkReconciler) reconcileNetwork(ctx context.Context, req ctrl.Request) (net *starv1.Network, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	net = &starv1.Network{}
	err = r.Get(ctx, req.NamespacedName, net)
	if err != nil {
		if errors.IsNotFound(err) {
			err = nil
			log.Info("Network resource not found. Ignoring since object must be deleted")
			res = &ctrl.Result{}
			return
		}
		log.Error(err, "Failed to get Network")
		res = &ctrl.Result{}
		return
	}
	log.Info("Found", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
	return
}

// 2. Reconcile Network Secret reference.
func (r *NetworkReconciler) reconcileSecretReference(ctx context.Context, req ctrl.Request, net *starv1.Network) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if net.SecretRef == (corev1.SecretReference{}) {
		log.Info("Network SecretRef not set. Generating and setting", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(net.GroupVersionKind())
		patch.SetNamespace(net.Namespace)
		patch.SetName(net.Name)
		patch.UnstructuredContent()["secretRef"] = map[string]interface{}{
			"name": genNetworkSecretName(net.Name),
		}
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "secret_ref",
		})

		if err != nil {
			log.Error(err, "Failed to patch Secret reference")
			res = &ctrl.Result{}
			return
		}

		log.Error(err, "Patched Secret refence", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		res = &ctrl.Result{Requeue: true}
		return
	}

	return
}

// 2.a. Generate Network Secret name.
func genNetworkSecretName(n string) string {
	return names.SimpleNameGenerator.GenerateName(n + "-server-")
}

// 3. Reconcile Network Secret reference for WireGuard Quick Config.
func (r *NetworkReconciler) reconcileSecretConfigReference(ctx context.Context, req ctrl.Request, net *starv1.Network) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if net.ConfigSecretRef == (starv1.LocalSecretReference{}) {
		log.Info("Network ConfigSecretRef not set. Generating and setting", "Network.Namespace", net.Namespace, "Network.Name", net.Name)
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(net.GroupVersionKind())
		patch.SetNamespace(net.Namespace)
		patch.SetName(net.Name)
		patch.UnstructuredContent()["configSecretRef"] = map[string]interface{}{
			"name": genServerConfigSecretName(net.Name),
		}
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "config_secret_ref",
		})

		if err != nil {
			log.Error(err, "Failed to patch Secret reference for WireGuard Quick Config")
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	}
	// TODO: SecretRef.Namespace is to be set?
	return
}

// 3.a. Generate Server Config Secret name.
func genServerConfigSecretName(n string) string {
	return names.SimpleNameGenerator.GenerateName(n + "-server-wgconf-")
}

// 4. Reconcile Secret for general purpose.
func (r *NetworkReconciler) reconcileSecret(ctx context.Context, req ctrl.Request, net *starv1.Network) (pk wireguard.PrivateKey, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	sec := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: net.SecretRef.Name, Namespace: net.SecretRef.Namespace}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil
		var s *corev1.Secret
		s, err = r.secret(net)
		if err != nil {
			log.Error(err, "Failed to create new Secret")
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret", "Secret.Namespace", s.Namespace, "Secret.Name", s.Name)
		err = r.Create(ctx, s)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Secret.Namespace", s.Namespace, "Secret.Name", s.Name)
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

	srvPriv := sec.Data[srvPrivateKeySecretKey]
	if len(srvPriv) == 0 {
		log.Info("Skipped parsing private key because not present", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
	} else if len(srvPriv) != wireguard.PrivateKeySize {
		err = fmt.Errorf("length of private key in Secret is %d while expecting length %d", len(srvPriv), wireguard.PrivateKeySize)
		log.Error(err, "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
		res = &ctrl.Result{}
		return
	} else {
		copy(pk[:], srvPriv)
	}

	return
}

// 4.a. Generate Secret for general purpose.
func (r *NetworkReconciler) secret(m *starv1.Network) (*corev1.Secret, error) {
	p, err := wireguard.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	ls := r.labels(m.Name)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.SecretRef.Name,
			Namespace: m.Namespace,
			Labels:    ls,
		},
		Data: map[string][]byte{
			srvPrivateKeySecretKey: p[:],
		},
	}

	ctrl.SetControllerReference(m, sec, r.Scheme)
	return sec, nil
}

// 5. Reconcile Secret for WireGuard Quick Config.
func (r *NetworkReconciler) reconcileSecretConfig(ctx context.Context, req ctrl.Request, net *starv1.Network, pk wireguard.PrivateKey) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	sec := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: net.ConfigSecretRef.Name, Namespace: net.Namespace}, sec)
	if err != nil && errors.IsNotFound(err) {
		err = nil
		var s *corev1.Secret
		s, err = r.secretConf(net, pk)
		if err != nil {
			log.Error(err, "Failed to create new Secret for WireGuard Quick Config")
			res = &ctrl.Result{}
			return
		}
		log.Info("Creating a new Secret for WireGuard Quick Config", "Secret.Namespace", s.Namespace, "Secret.Name", s.Name)
		err = r.Create(ctx, s)
		if err != nil {
			log.Error(err, "Failed to create new Secret", "Secret.Namespace", s.Namespace, "Secret.Name", s.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{Requeue: true}
		return
	} else if err != nil {
		log.Error(err, "Failed to get Deployment")
		res = &ctrl.Result{}
		return
	}

	wg0Conf := sec.Data[wg0ConfKey]
	if len(pk) == 0 {
		log.Info("Skipped checking updates for server WireGuard Quick Config because server private key is not present")
		return
	} else {
		var wg0ConfDesired string
		wg0ConfDesired, err = serverConf(pk, *net)
		if err != nil {
			log.Error(err, "Failed to construct a server config file content")
			res = &ctrl.Result{}
			return
		}
		if !bytes.Equal(wg0Conf, []byte(wg0ConfDesired)) {
			log.Info("Updating Secret for WireGuard Quick Config", "Secret.Namespace", sec.Namespace, "Secret.Name", sec.Name)
			sec.Data[wg0ConfKey] = []byte(wg0ConfDesired)
			r.Update(ctx, sec)
			res = &ctrl.Result{RequeueAfter: 3 * time.Second}
			return
		}
	}

	return
}

// 5.a. Generate Secret for WireGuard Quick Config.
func (r *NetworkReconciler) secretConf(m *starv1.Network, priv wireguard.PrivateKey) (*corev1.Secret, error) {
	srvConf, err := serverConf(priv, *m)
	if err != nil {
		return nil, err
	}

	ls := r.labels(m.Name)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.ConfigSecretRef.Name,
			Namespace: m.Namespace,
			Labels:    ls,
		},
		StringData: map[string]string{
			wg0ConfKey: srvConf,
		},
	}

	ctrl.SetControllerReference(m, sec, r.Scheme)
	return sec, nil
}

// 5.b. Generate server WireGuard Quick Config content.
func serverConf(pk wireguard.PrivateKey, m starv1.Network) (string, error) {
	var as wireguard.IPAddresses
	for i, ip := range m.Spec.ServerIPs {
		a, err := wireguard.ParseIPAddress(ip)
		if err != nil {
			return "", fmt.Errorf("error in %d-th server ip %q: %s", i+1, ip, err)
		}
		as = append(as, a)
	}

	return wireguard.BuildSrvConf(wireguard.ServerConf{
		IPv4Enabled:      m.Spec.IPv4Enabled,
		IPv6Enabled:      m.Spec.IPv6Enabled,
		ListenPort:       wgPort,
		ServerPrivateKey: pk,
		ServerAddress:    as,
		// TODO: after creating Device controller
		Devices: []wireguard.ServerConfDevice{},
	})
}

// 6. Reconcile Deployment.
func (r *NetworkReconciler) reconcileDeployment(ctx context.Context, req ctrl.Request, net *starv1.Network) (dep *appsv1.Deployment, res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	dep = &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: deploymentName(net.Name), Namespace: net.Namespace}, dep)
	if err != nil && errors.IsNotFound(err) {
		err = nil
		d := r.deployment(net)
		log.Info("Creating a new Deployment", "Deployment.Namespace", d.Namespace, "Deployment.Name", d.Name)
		err = r.Create(ctx, dep)
		if err != nil {
			log.Error(err, "Failed to create new Deployment", "Deployment.Namespace", d.Namespace, "Deployment.Name", d.Name)
			res = &ctrl.Result{}
			return
		}
		// Deployment created successfully - return and requeue
		res = &ctrl.Result{Requeue: true}
		return
	} else if err != nil {
		log.Error(err, "Failed to get Deployment")
		res = &ctrl.Result{}
		return
	}
	return
}

// 6.a. Generate Deployment.
func (r *NetworkReconciler) deployment(m *starv1.Network) *appsv1.Deployment {
	ls := r.labels(m.Name)
	replicas := *m.Spec.Replicas
	privileged := true

	wgImg := m.Spec.WireguardImage
	if wgImg == "" {
		wgImg = wgImgDefault
	}

	var mode int32 = 0400

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
						Image: wgImg,
						Name:  "star-server",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
						},
						ImagePullPolicy: m.Spec.ImagePullPolicy,
						Env:             m.Spec.Env,
						Command:         hangCommand,
						Ports: []corev1.ContainerPort{{
							ContainerPort: wgPort,
							Name:          "wireguard",
						}},
						Lifecycle: &corev1.Lifecycle{
							PostStart: &corev1.Handler{
								Exec: &corev1.ExecAction{
									Command: upCommand,
								},
							},
							PreStop: &corev1.Handler{
								Exec: &corev1.ExecAction{
									Command: downCommand,
								},
							},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "wireguard",
							MountPath: "/etc/wireguard",
							ReadOnly:  true,
						}},
					}},
					ImagePullSecrets: m.Spec.ImagePullSecrets,
					Volumes: []corev1.Volume{{
						Name: "wireguard",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  m.ConfigSecretRef.Name,
								DefaultMode: &mode,
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

// 6.a.a. Generate Deployment name.
func deploymentName(n string) string {
	return n + "-server"
}

// 7. Reconcile Deployment Replicas.
func (r *NetworkReconciler) reconcileDeploymentReplicas(ctx context.Context, req ctrl.Request, net *starv1.Network, dep *appsv1.Deployment) (res *ctrl.Result, err error) {
	log := log.FromContext(ctx)

	if *dep.Spec.Replicas != *net.Spec.Replicas {
		patch := &unstructured.Unstructured{}
		patch.SetGroupVersionKind(dep.GroupVersionKind())
		patch.SetNamespace(dep.Namespace)
		patch.SetName(dep.Name)
		patch.UnstructuredContent()["spec"] = map[string]interface{}{
			"replicas": *net.Spec.Replicas,
		}
		err = r.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "deployment_replicas",
		})
		if err != nil {
			log.Error(err, "Failed to patch Deployment replicas", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
			res = &ctrl.Result{}
			return
		}
		res = &ctrl.Result{RequeueAfter: time.Minute}
		return
	}
	return
}

// Common labels for resources managed by Network.
func (NetworkReconciler) labels(name string) map[string]string {
	return map[string]string{
		"vpn-planet":      "true",
		"star.vpn-planet": "true",
		"app":             "network",
		"name":            name,
	}
}

func getDevices() int32 {
	// TODO: after devices
	return 3
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&starv1.Network{}).
		Complete(r)
}
