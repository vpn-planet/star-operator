package log

import (
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// RuntimeLog is a base parent logger for use inside star-operator.
	RuntimeLog logr.Logger
)

func init() {
	RuntimeLog = log.Log.WithName("star-operator")
}
