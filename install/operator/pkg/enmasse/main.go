package enmasse

import (
	"os"

	"github.com/operator-framework/operator-sdk/pkg/sdk"
	api "github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
	"k8s.io/api/core/v1"
)

// ReconcileConfigMap
func ReconcileConfigMap(configmap *v1.ConfigMap, deleted bool) error {
	if val, ok := configmap.ObjectMeta.Labels["type"]; ok && val == "address-space-plan" {
		return reconcileAddressSpacePlan(configmap, deleted)
	}
	return nil
}

// ReconcileConnection
func ReconcileConnection(connection *api.Connection, deleted bool) error {
	switch connection.Status.Phase {
	case "":
		err := createConnection(connection, os.Getenv("SYNDESIS_SERVER_SERVICE_HOST"))
		if err != nil {
			connection.Status.Phase = "failed_creation"
			connection.Status.Ready = false
			sdk.Update(connection)
			return err
		}
		connection.Status.Phase = "ready"
		connection.Status.Ready = true
		return sdk.Update(connection)
	}

	return nil
}

func reconcileAddressSpacePlan(addressSpacePlan *v1.ConfigMap, deleted bool) error {
	return nil
}
