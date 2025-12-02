package vexhub

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Index structures
type Index struct {
	UpdatedAt time.Time     `json:"updated_at"`
	Packages  []PackageInfo `json:"packages"`
}

type PackageInfo struct {
	ID       string `json:"id"`
	Location string `json:"location"`
	Format   string `json:"format,omitempty"` // "openvex" or "csaf", defaults to "openvex"
}

// VEXHubRepo manages the VEX repository
type VEXHubRepo struct {
	mu          sync.RWMutex
	index       *Index
	vexDocument *vex.VEX
	k8sClient   client.Client
}

// NewVEXHubRepository creates a new VEX repository server
func NewVEXHubRepository(ctx context.Context, k8sClient client.Client) (*VEXHubRepo, error) {
	server := &VEXHubRepo{
		index:       &Index{},
		vexDocument: &vex.VEX{},
		k8sClient:   k8sClient,
	}

	return server, nil
}

// Update updates the index.json and vex document contents
func (s *VEXHubRepo) Update(ctx context.Context) error {
	vexDoc, err := s.getVEXDocument(ctx)
	if err != nil {
		return fmt.Errorf("failed to read VEX document from configmap: %w", err)
	}
	var packages []PackageInfo
	for _, statement := range vexDoc.Statements {
		for _, product := range statement.Products {
			purl := product.Identifiers[vex.PURL]
			pkg := PackageInfo{
				ID:       purlClean(purl),
				Location: configMapVex,
			}
			packages = append(packages, pkg)
		}
	}
	// update index
	s.index.UpdatedAt = time.Now().UTC()
	s.index.Packages = packages
	// update vex document
	s.vexDocument = vexDoc

	return nil
}
