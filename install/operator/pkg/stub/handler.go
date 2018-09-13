package stub

import (
	"context"

	"github.com/operator-framework/operator-sdk/pkg/sdk"
	"github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
	"github.com/syndesisio/syndesis/install/operator/pkg/enmasse"
	"github.com/syndesisio/syndesis/install/operator/pkg/openshift"
	"github.com/syndesisio/syndesis/install/operator/pkg/syndesis"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/syndesisio/syndesis/install/operator/pkg/syndesis/api"
	"k8s.io/api/core/v1"
)

func NewHandler(syndesisAPIClient api.Client) sdk.Handler {
	return &Handler{
		syndesisAPIClient: syndesisAPIClient,
	}
}

type Handler struct {
	// Fill me
	syndesisAPIClient api.Client
}

func (h *Handler) Handle(ctx context.Context, event sdk.Event) error {
	switch o := event.Object.(type) {
	case *v1alpha1.Syndesis:
		return syndesis.Reconcile(o, event.Deleted)
	case *v1.ConfigMap:
		return enmasse.ReconcileConfigmap(o, event.Deleted)
	case *routev1.Route:
		return openshift.ReconcileRoute(o, event.Deleted)
	case *v1alpha1.Connection:
		return syndesis.ReconcileConnection(o, event.Deleted, h.syndesisAPIClient)
	}
	return nil
}
