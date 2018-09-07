package main

import (
	"context"
	"runtime"

	"github.com/syndesisio/syndesis/install/operator/pkg/syndesis/legacy"

	// Load Openshift types
	_ "github.com/syndesisio/syndesis/install/operator/pkg/openshift"

	"github.com/operator-framework/operator-sdk/pkg/sdk"
	"github.com/operator-framework/operator-sdk/pkg/util/k8sutil"
	sdkVersion "github.com/operator-framework/operator-sdk/version"
	"github.com/syndesisio/syndesis/install/operator/pkg/stub"

	"flag"

	"github.com/sirupsen/logrus"
	configuration "github.com/syndesisio/syndesis/install/operator/pkg/syndesis/configuration"
)

func printVersion() {
	logrus.Infof("Go Version: %s", runtime.Version())
	logrus.Infof("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	logrus.Infof("operatorof the Syndesis infrastructure elements-sdk Version: %v", sdkVersion.Version)
}

func main() {
	printVersion()

	configuration.TemplateLocation = flag.String("template", "/conf/syndesis-template.yml", "Path to template used for installation")
	flag.Parse()
	logrus.Infof("Using template %s", *configuration.TemplateLocation)

	resource := "syndesis.io/v1alpha1"
	kind := "Syndesis"
	namespace, err := k8sutil.GetWatchNamespace()
	if err != nil {
		logrus.Fatalf("Failed to get watch namespace: %v", err)
	}

	resyncPeriod := 5
	ctx := context.TODO()

	legacyController := legacy.NewLegacyController(namespace)
	legacyController.Start(ctx)

	logrus.Infof("Watching %s, %s, %s, %d", resource, kind, namespace, resyncPeriod)
	sdk.Watch(resource, kind, namespace, resyncPeriod)
	logrus.Infof("Watching %s, %s, %s, %d", resource, "Connection", namespace, resyncPeriod)
	sdk.Watch(resource, "Connection", namespace, resyncPeriod)
	sdk.Watch("v1", "ConfigMap", namespace, resyncPeriod)
	sdk.Handle(stub.NewHandler())
	sdk.Run(ctx)
}
