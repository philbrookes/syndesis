package enmasse

import (
	"os"

	glog "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"

	"github.com/operator-framework/operator-sdk/pkg/sdk"
	"github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Reconcile the state
func Reconcile(configmap *v1.ConfigMap, deleted bool) error {
	if val, ok := configmap.ObjectMeta.Labels["type"]; ok && val == "address-space-plan" {
		glog.Infof("Reconciling address-space-plan: '%v'", configmap.ObjectMeta.Name)
		return reconcileAddressSpacePlan(configmap, deleted)
	}
	return nil
}

func reconcileAddressSpacePlan(addressSpacePlan *v1.ConfigMap, deleted bool) error {
	asp := &v1alpha1.Connection{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Connection",
			APIVersion: "syndesis.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: os.Getenv("WATCH_NAMESPACE"),
		},
	}
	err := sdk.Get(asp)
	if err != nil {
		glog.Infof("getting asp gave error: %v", err.Error())
		return err
	}
	return nil
}
