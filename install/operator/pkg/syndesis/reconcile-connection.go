package syndesis

import (
	"github.com/operator-framework/operator-sdk/pkg/sdk"
	v1alpha1 "github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
	"github.com/syndesisio/syndesis/install/operator/pkg/syndesis/api"
)

// ReconcileConnection
func ReconcileConnection(connection *v1alpha1.Connection, deleted bool, syndesisAPIClient api.Client) error {
	switch connection.Status.Phase {
	case "":
		err := syndesisAPIClient.CreateConnection(connection)
		if err != nil {
			return err
		}
		connection.Status.Phase = "ready"
		connection.Status.Ready = true
		return sdk.Update(connection)
	}
	return nil
}
