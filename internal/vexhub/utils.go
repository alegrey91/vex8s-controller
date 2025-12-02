package vexhub

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

var configMapVex = "vex8s.json"
var indexJSONFile = "index.json"

// purlClean returns the cleaned version of input PURL
func purlClean(purl string) string {
	return strings.Split(purl, "@")[0]
}

// generateTarGz generates a tar.gz archive of the repository
// The tar.gz archive has the following structure:
// vex-data.tar.gz
// ├── index.json
// └── vex8s.json
func (s *VEXHubRepo) generateTarGz(w io.Writer) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gzWriter := gzip.NewWriter(w)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Add index.json
	indexData, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}
	if err := addFileToTar(tarWriter, indexJSONFile, indexData); err != nil {
		return err
	}

	// Add vex8s.json
	vexData, err := json.MarshalIndent(s.vexDocument, "", "  ")
	if err != nil {
		return err
	}
	if err := addFileToTar(tarWriter, configMapVex, vexData); err != nil {
		return err
	}
	return nil
}

// getVEXDocument retrieve information from the vex8s.json configmap
// merging the VEX documents generated from pods all together,
// returning a single VEX document.
func (s *VEXHubRepo) getVEXDocument(ctx context.Context) (*vex.VEX, error) {
	vexConfigMap := &corev1.ConfigMap{}
	err := s.k8sClient.Get(ctx, types.NamespacedName{
		Name: configMapVex,
		// TODO: replace it later
		Namespace: "default",
	}, vexConfigMap)
	if err != nil {
		return nil, err
	}

	// Merge the VEX documents in the configMap,
	// all together.
	var vexDocs []*vex.VEX
	for _, data := range vexConfigMap.Data {
		vexDoc, err := vex.Parse([]byte(data))
		if err != nil {
			return nil, err
		}
		vexDocs = append(vexDocs, vexDoc)
	}
	vexDocument, err := vex.MergeDocuments(vexDocs)
	if err != nil {
		return nil, err
	}
	return vexDocument, nil
}

// addFileToTar adds file content into a tar archive
func addFileToTar(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err := tw.Write(data)
	return err
}
