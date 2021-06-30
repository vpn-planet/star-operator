package controllers

import (
	starv1 "github.com/vpn-planet/star-operator/api/v1"

	logf "github.com/vpn-planet/star-operator/internal/log"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var enqueueLog = logf.RuntimeLog.WithName("eventhandler").WithName("deviceEnqueueRequestForNetwork")

type deviceEnqueueRequestForNetwork struct{}

// Create implements EventHandler.
func (e *deviceEnqueueRequestForNetwork) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	if evt.Object == nil {
		enqueueLog.Error(nil, "CreateEvent received with no metadata", "event", evt)
		return
	}
	switch obj := evt.Object.(type) {
	case *starv1.Device:
		q.Add(reconcile.Request{NamespacedName: obj.NetworkNamespacedName()})
	default:
		enqueueLog.Error(nil, "CreateEvent received unexpected resource, not Network", "event", evt)
		return
	}
}

// Update implements EventHandler.
func (e *deviceEnqueueRequestForNetwork) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	switch {
	case evt.ObjectNew != nil:
		switch obj := evt.ObjectNew.(type) {
		case *starv1.Device:
			q.Add(reconcile.Request{NamespacedName: obj.NetworkNamespacedName()})
		default:
			enqueueLog.Error(nil, "UpdateEvent ObjectNew received unexpected resource, not Network", "event", evt)
			return
		}
	case evt.ObjectOld != nil:
		switch obj := evt.ObjectOld.(type) {
		case *starv1.Device:
			q.Add(reconcile.Request{NamespacedName: obj.NetworkNamespacedName()})
		default:
			enqueueLog.Error(nil, "UpdateEvent ObjectOld received unexpected resource, not Network", "event", evt)
			return
		}
	default:
		enqueueLog.Error(nil, "UpdateEvent received with no metadata", "event", evt)
	}
}

// Delete implements EventHandler.
func (e *deviceEnqueueRequestForNetwork) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	if evt.Object == nil {
		enqueueLog.Error(nil, "DeleteEvent received with no metadata", "event", evt)
		return
	}
	switch obj := evt.Object.(type) {
	case *starv1.Device:
		q.Add(reconcile.Request{NamespacedName: obj.NetworkNamespacedName()})
	default:
		enqueueLog.Error(nil, "DeleteEvent received unexpected resource, not Network", "event", evt)
		return
	}
}

// Generic implements EventHandler.
func (e *deviceEnqueueRequestForNetwork) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	if evt.Object == nil {
		enqueueLog.Error(nil, "GenericEvent received with no metadata", "event", evt)
		return
	}
	switch obj := evt.Object.(type) {
	case *starv1.Device:
		q.Add(reconcile.Request{NamespacedName: obj.NetworkNamespacedName()})
	default:
		enqueueLog.Error(nil, "GenericEvent received unexpected resource, not Network", "event", evt)
		return
	}
}
