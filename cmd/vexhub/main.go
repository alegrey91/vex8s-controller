/*
Copyright 2025.

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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"kubewarden.io/vex8s-controller/internal/vexhub"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var certFile string
	var keyFile string
	var port string
	flag.StringVar(&certFile, "cert-path", "", "The name of the certificate file.")
	flag.StringVar(&keyFile, "key-path", "", "The name of the key file.")
	flag.StringVar(&port, "port", "8080", "The number of the port.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	ctx := context.Background()

	setupLog.Info("Setting up k8s client")
	config := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "Failed to set up k8s client")
		os.Exit(1)
	}

	setupLog.Info("Setting up VEX Hub repository")
	vexHubRepo, err := vexhub.NewVEXHubRepository(ctx, k8sClient)
	if err != nil {
		setupLog.Error(err, "Failed to set up VEX Hub repository")
		os.Exit(1)
	}
	setupLog.Info("Starting updating VEX Hub repository")
	tickerChannel := time.NewTicker(15 * time.Second)
	go func() {
		for range tickerChannel.C {
			err := vexHubRepo.Update(ctx)
			if err != nil {
				fmt.Println(err)
				setupLog.Error(err, "Failed to update VEX Hub repository")
			}
			setupLog.Info("VEX Hub repository updated")
		}
	}()

	// Set up routes
	http.HandleFunc("/.well-known/vex-repository.json", vexHubRepo.HandleManifest)
	http.HandleFunc("/vex-data.tar.gz", vexHubRepo.HandleTarGz)
	http.HandleFunc("/index.json", vexHubRepo.HandleIndex)

	setupLog.Info(fmt.Sprintf("VEX Hub repository server starting on port %s", port))
	setupLog.Info(fmt.Sprintf("Manifest: https://localhost:%s/.well-known/vex-repository.json", port))
	setupLog.Info(fmt.Sprintf("Archive: https://localhost:%s/vex-data.tar.gz", port))

	if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
