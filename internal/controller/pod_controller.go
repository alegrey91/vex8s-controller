package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vex8s "github.com/alegrey91/vex8s/pkg/mitigation"
	"github.com/alegrey91/vex8s/pkg/vex"
	sbomscannerstorage "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

const configMapVex = "vex8s.json"

type VEXPodReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// SetupWithManager sets up the controller with the Manager
func (r *VEXPodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// Reconcile handles Pod events
func (r *VEXPodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Pod event detected", "reconciliation start-up", req.Name)

	// Ensure SBOMscanner is installed
	vulnReportList := &sbomscannerstorage.VulnerabilityReportList{}
	if err := r.List(ctx, vulnReportList); err != nil {
		logger.Error(err, "SBOMscanner not installed")
		return ctrl.Result{}, err
	}

	// Fetch the Pod
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if errors.IsNotFound(err) {
			// Pod deleted, nothing to do
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Pod")
		return ctrl.Result{}, err
	}

	// Delete key/value in ConfigMap if pod is not running or pending
	if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
		logger.Info("Deleting pod VEX document from ConfigMap", "pod", pod.Name)
		err := r.deleteVEXKeyFromConfigMap(ctx, pod)
		if err != nil {
			logger.Error(err, "Failed to delete key/value in ConfigMap")
		}
		return ctrl.Result{}, nil
	}

	var totalMitigated []vex8s.CVE
	// Process each container in the pod
	for _, container := range pod.Spec.Containers {
		logger.Info("Processing container", "container", container.Name, "image", container.Image)

		// Find VulnerabilityReport for this container image.
		// If Pod is scheduled, we assume we already have the VulnerabilityReport.
		vulnReport, err := r.findVulnerabilityReport(ctx, pod.Namespace, container.Image)
		if err != nil {
			logger.Error(err, "Failed to find VulnerabilityReport", "image", container.Image)
			continue // Continue with next container
		}

		if vulnReport == nil {
			logger.Info("No VulnerabilityReport found for image", "image", container.Image)
			continue
		}

		// Extract CVEs from VulnerabilityReport
		cves := r.extractCVEs(vulnReport)
		logger.Info("Extracted CVEs", "count", len(cves), "image", container.Image)

		// Check mitigation status for each CVE
		var mitigated []vex8s.CVE
		for _, cve := range cves {
			if vex8s.IsCVEMitigated(cve, &pod.Spec, &container) {
				logger.Info("CVE is mitigated", "cve", cve.ID, "image", container.Image)
				mitigated = append(mitigated, cve)
			}
		}
		totalMitigated = append(totalMitigated, mitigated...)
	}

	// Generate VEX document
	if len(totalMitigated) == 0 {
		logger.Info("No mitigations have been found", "pod", pod.Name)
		return ctrl.Result{}, nil
	}
	vexInfo := vex.VEXInfo{
		Author:     "vex8s-controller",
		AuthorRole: "Kubernetes Controller",
		// Tooling value is not negotiable
		Tooling: "vex8s",
	}
	vexDoc, err := vex.GenerateVEX(totalMitigated, vexInfo)
	if err != nil {
		logger.Error(err, "Failed to generate VEX document", "pod", pod.Name)
		return ctrl.Result{}, err
	}

	// Write VEX content
	vexContent, err := json.MarshalIndent(vexDoc, "", "  ")
	if err != nil {
		logger.Error(err, "Failed to marshal VEX document", "pod", pod.Name)
		return ctrl.Result{}, err
	}
	// only for debugging purpose
	fmt.Println(string(vexContent))

	// Save VEX document to ConfigMap
	if err := r.saveVEXToConfigMap(ctx, pod, string(vexContent)); err != nil {
		logger.Error(err, "Failed to save VEX document to ConfigMap", "pod", pod.Name)
		return ctrl.Result{}, err
	}
	logger.Info("Successfully saved VEX document", "pod", pod.Name, "pod", pod.Name)

	return ctrl.Result{}, nil
}

// findVulnerabilityReport searches for a VulnerabilityReport matching the container image
func (r *VEXPodReconciler) findVulnerabilityReport(ctx context.Context, namespace, image string) (*sbomscannerstorage.VulnerabilityReport, error) {
	logger := log.FromContext(ctx)

	// List all VulnerabilityReports in the namespace
	vulnReportList := &sbomscannerstorage.VulnerabilityReportList{}
	if err := r.List(ctx, vulnReportList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list VulnerabilityReports: %w", err)
	}

	// Normalize the image name for comparison
	normalizedImage := normalizeImageName(image)
	// eg. normalized image:  docker.io/localhost:5000/test-image

	// Search for matching report
	for _, report := range vulnReportList.Items {
		// Check if the report matches this image
		if report.ImageMetadata.Repository == normalizedImage {
			logger.Info("Found matching VulnerabilityReport", "report", report.Name, "image", image)
			return &report, nil
		}
	}

	return nil, nil // No matching report found
}

// extractCVEs converts VulnerabilityReport vulnerabilities to CVE struct list
func (r *VEXPodReconciler) extractCVEs(vulnReport *sbomscannerstorage.VulnerabilityReport) []vex8s.CVE {
	var cves []vex8s.CVE

	// Extract vulnerabilities from the report
	// Adjust based on actual VulnerabilityReport structure
	for _, results := range vulnReport.Report.Results {
		for _, vuln := range results.Vulnerabilities {
			cve := vex8s.CVE{
				ID:   vuln.CVE,
				PURL: vuln.PURL,
				CWEs: vuln.CWES,
			}
			cves = append(cves, cve)
		}
	}

	return cves
}

// normalizeImageName removes tag/digest and standardizes image name for comparison
func normalizeImageName(image string) string {
	// Remove digest if present (e.g., @sha256:...)
	if idx := strings.Index(image, "@"); idx != -1 {
		image = image[:idx]
	}

	// Remove tag if present (e.g., :latest)
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		// Make sure it's not part of the registry port
		if !strings.Contains(image[idx:], "/") {
			image = image[:idx]
		}
	}

	if strings.Contains(image, "/") {
		imageComponents := strings.Split(image, "/")
		image = imageComponents[len(imageComponents)-1]
	}

	return strings.ToLower(image)
}

// saveVEXToConfigMap saves the VEX document to a ConfigMap
func (r *VEXPodReconciler) saveVEXToConfigMap(ctx context.Context, pod *corev1.Pod, vexDoc string) error {
	logger := log.FromContext(ctx)

	// Create ConfigMap name (use pod name + container name)
	podID := fmt.Sprintf("vex-%s", pod.Name)

	// Create or update ConfigMap
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapVex,
			Namespace: pod.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "vex8s-controller",
				"app.kubernetes.io/component":  "vex-document",
			},
			Annotations: map[string]string{
				"vex8s.io/generated-at": time.Now().UTC().Format(time.RFC3339),
			},
		},
		Data: map[string]string{
			podID: vexDoc,
		},
	}

	// Try to get existing ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      configMapVex,
		Namespace: pod.Namespace,
	}, existingConfigMap)

	if err != nil {
		if errors.IsNotFound(err) {
			// Create new ConfigMap
			logger.Info("Creating new VEX ConfigMap", "name", configMapVex)
			if err := r.Create(ctx, configMap); err != nil {
				return fmt.Errorf("failed to create ConfigMap: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get ConfigMap: %w", err)
	}

	// Patch existing ConfigMap
	logger.Info("Updating existing VEX ConfigMap", "name", configMapVex)
	patch := client.MergeFrom(existingConfigMap.DeepCopy())
	if existingConfigMap.Data == nil {
		existingConfigMap.Data = map[string]string{}
	}
	existingConfigMap.Data[podID] = vexDoc
	existingConfigMap.Labels = configMap.Labels
	existingConfigMap.Annotations = configMap.Annotations

	if err := r.Patch(ctx, existingConfigMap, patch); err != nil {
		return fmt.Errorf("failed to update ConfigMap: %w", err)
	}

	return nil
}

func (r *VEXPodReconciler) deleteVEXKeyFromConfigMap(ctx context.Context, pod *corev1.Pod) error {
	var cm corev1.ConfigMap
	podID := fmt.Sprintf("vex-%s", pod.Name)
	err := r.Get(ctx, client.ObjectKey{
		Name:      configMapVex,
		Namespace: pod.Namespace},
		&cm)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil // ConfigMap does not exist, nothing to delete
		}
		return err
	}

	// Delete the key from the Data map
	delete(cm.Data, podID)

	// Now apply the update
	return r.Update(ctx, &cm)
}
