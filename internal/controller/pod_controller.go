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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vex8s "github.com/alegrey91/vex8s/pkg/mitigation"
	"github.com/alegrey91/vex8s/pkg/vex"
	sbomscannerstorage "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

type PodVEXReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// SetupWithManager sets up the controller with the Manager
func (r *PodVEXReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// Reconcile handles Pod events
func (r *PodVEXReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("New pod detected", "reconciliation start-up", req.Name)

	// TODO: first of all we should
	// ensure that SBOMscanner is installed.

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

	// Skip if pod is not running or pending
	if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
		logger.Info("Skipping pod - not in Running or Pending phase", "phase", pod.Status.Phase)
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

	// TODO: Store mitigation results, generate VEX document, etc.
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
		return ctrl.Result{}, fmt.Errorf("Failed to generate VEX document: %w", err)
	}

	// Write VEX content
	vexContent, err := json.MarshalIndent(vexDoc, "", "  ")
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("Failed to marshal VEX document: %w", err)
	}
	// only for debugging purpose
	fmt.Println(string(vexContent))

	// Save VEX document to ConfigMap
	if err := r.saveVEXToConfigMap(ctx, pod, string(vexContent)); err != nil {
		return ctrl.Result{}, fmt.Errorf("Failed to save VEX document to ConfigMap: %w", err)
	}
	logger.Info("Successfully saved VEX document", "pod", pod.Name, "pod", pod.Name)

	return ctrl.Result{}, nil
}

// findVulnerabilityReport searches for a VulnerabilityReport matching the container image
func (r *PodVEXReconciler) findVulnerabilityReport(ctx context.Context, namespace, image string) (*sbomscannerstorage.VulnerabilityReport, error) {
	logger := log.FromContext(ctx)

	// List all VulnerabilityReports in the namespace
	vulnReportList := &sbomscannerstorage.VulnerabilityReportList{}
	if err := r.List(ctx, vulnReportList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list VulnerabilityReports: %w", err)
	}

	// Normalize the image name for comparison
	normalizedImage := normalizeImageName(image)
	fmt.Println("normalized image: ", normalizedImage)
	// normalized image:  docker.io/localhost:5000/test-image

	// Search for matching report
	for _, report := range vulnReportList.Items {
		// Check if the report matches this image
		// This depends on how sbomscanner stores image references
		// Common fields might be: .spec.artifact.image, .metadata.labels["image"], etc.

		// Option 1: Check artifact field (adjust based on actual API)
		if report.ImageMetadata.Repository == normalizedImage {
			logger.Info("Found matching VulnerabilityReport", "report", report.Name, "image", image)
			return &report, nil
		}

		// Option 2: Check labels
		if reportImage, ok := report.Labels["image"]; ok {
			if normalizeImageName(reportImage) == normalizedImage {
				logger.Info("Found matching VulnerabilityReport via label", "report", report.Name, "image", image)
				return &report, nil
			}
		}

		// Option 3: Check by naming convention (e.g., reports named after image digest)
		// Add your specific matching logic here
	}

	return nil, nil // No matching report found
}

// extractCVEs converts VulnerabilityReport vulnerabilities to CVE struct list
func (r *PodVEXReconciler) extractCVEs(vulnReport *sbomscannerstorage.VulnerabilityReport) []vex8s.CVE {
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
func (r *PodVEXReconciler) saveVEXToConfigMap(ctx context.Context, pod *corev1.Pod, vexDoc string) error {
	logger := log.FromContext(ctx)

	// Create ConfigMap name (use pod name + container name)
	configMapName := fmt.Sprintf("vex-%s", pod.Name)

	// Create or update ConfigMap
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: pod.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "vex8s-controller",
				"app.kubernetes.io/component":  "vex-document",
				"vex8s.io/pod":                 pod.Name,
			},
			Annotations: map[string]string{
				"vex8s.io/generated-at": time.Now().UTC().Format(time.RFC3339),
				"vex8s.io/pod-uid":      string(pod.UID),
			},
		},
		Data: map[string]string{
			"vex.json": vexDoc,
		},
	}

	// Set Pod as owner of ConfigMap for automatic cleanup
	if err := controllerutil.SetControllerReference(pod, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}

	// Try to get existing ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      configMapName,
		Namespace: pod.Namespace,
	}, existingConfigMap)

	if err != nil {
		if errors.IsNotFound(err) {
			// Create new ConfigMap
			logger.Info("Creating new VEX ConfigMap", "name", configMapName)
			if err := r.Create(ctx, configMap); err != nil {
				return fmt.Errorf("failed to create ConfigMap: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get ConfigMap: %w", err)
	}

	// Update existing ConfigMap
	logger.Info("Updating existing VEX ConfigMap", "name", configMapName)
	existingConfigMap.Data = configMap.Data
	existingConfigMap.Labels = configMap.Labels
	existingConfigMap.Annotations = configMap.Annotations

	if err := r.Update(ctx, existingConfigMap); err != nil {
		return fmt.Errorf("failed to update ConfigMap: %w", err)
	}

	return nil
}
