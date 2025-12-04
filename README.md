# vex8s-controller

## Description

`vex8s-controller` is an add-on for [SBOMscanner](github.com/kubewarden/sbomscanner) project. Its purpose is to automatically generate VEX documents based on the workloads running in a kubernetes cluster. It integrates directly with SBOMscanner by monitoring `VulnerabilityReports` created for container images and producing corresponding VEX documents that reflect each workload's `SecurityContext`.

![vex8s-controller workflow](vex8s-controller.png)

Here's the workflow explained:

1. sbomscanner scans for images in registry
2. generates a VulnerabilityReport with the image CVEs
3. vex8s-controller triggers when a workload is scheduled on the cluster and generates a VEX document based on the workload SecurityContext configuration
4. the VEX document is provided by vex8s-controller using a VEX Hub repository
5. sbomscanner configure the VEXHub CRD to point to the internal vex8s-controller VEX Hub repository

## Goals
The objective is to build a kubernetes controller that uses the vex8s mitigation rules engine to generate VEX documents and serve them through an internal VEX Hub repository within the cluster. SBOMscanner can then be configured to consume VEX data directly from this in-cluster repository managed by vex8s-controller.

## Resources

* [vex8s](github.com/alegrey91/vex8s)
* [SBOMscanner](github.com/kubewarden/sbomscanner)
