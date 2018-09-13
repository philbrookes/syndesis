package openshift

import (
	routev1 "github.com/openshift/api/route/v1"
	"github.com/operator-framework/operator-sdk/pkg/sdk"
	"github.com/operator-framework/operator-sdk/pkg/util/k8sutil"
	"github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"strings"
)

func ReconcileRoute(route *routev1.Route, deleted bool) error {
	namespace, _ := k8sutil.GetWatchNamespace()
	//look for matching connection
	conn := &v1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name,
			Namespace: namespace,
		},
		TypeMeta: metav1.TypeMeta{
			APIVersion: "syndesis.io/v1alpha1",
			Kind:       "Connection",
		},
		Spec: v1alpha1.ConnectionSpec{
			URL:            route.Spec.Host,
			ConnectionType: "http",
		},
	}

	err := sdk.Get(conn)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return err
	}

	if deleted {
		return sdk.Delete(conn, sdk.WithDeleteOptions(metav1.NewDeleteOptions(0)))
	}

	return sdk.Create(conn)

}
