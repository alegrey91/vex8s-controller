package vexhub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// VEX Repository Manifest structures
type VEXRepository struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Versions    []Version `json:"versions"`
}

type Version struct {
	SpecVersion    string     `json:"spec_version"`
	Locations      []Location `json:"locations"`
	UpdateInterval string     `json:"update_interval"`
}

type Location struct {
	URL string `json:"url"`
}

// HandleManifest returns the VEX Hub manifest
func (s *VEXHubRepo) HandleManifest(w http.ResponseWriter, r *http.Request) {
	log.Println("manifest handler triggered")
	manifest := VEXRepository{
		Name:        "VEX Repository",
		Description: "VEX repository for vulnerability information",
		Versions: []Version{
			{
				SpecVersion: "0.1",
				Locations: []Location{
					{
						URL: fmt.Sprintf("https://%s/vex-data.tar.gz", r.Host),
					},
				},
				UpdateInterval: "30m",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest)
}

// HandleManifest returns the VEX Hub tar.gz
func (s *VEXHubRepo) HandleTarGz(w http.ResponseWriter, r *http.Request) {
	log.Println("targz handler triggered")
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=vex-data.tar.gz")

	if err := s.generateTarGz(w); err != nil {
		log.Printf("Error generating tar.gz: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// HandleManifest returns the VEX Hub index.json
func (s *VEXHubRepo) HandleIndex(w http.ResponseWriter, r *http.Request) {
	log.Println("index.json handler triggered")
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.index)
}
