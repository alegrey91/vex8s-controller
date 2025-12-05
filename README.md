# vex8s-controller

## Description

`vex8s-controller` is an add-on for [sbomscanner](https://github.com/kubewarden/sbomscanner). Its purpose is to automate the process of generating VEX documents based on the workloads configurations running in your cluster. It integrates directly with sbomscanner by monitoring `VulnerabilityReports` of your images and producing corresponding VEX documents that reflect the workload `SecurityContext`.

![vex8s-controller workflow](vex8s-controller.png)

Here's the workflow explained:

1. sbomscanner scans for images in the registry.
2. sbomscanner generates `VulnerabilityReports` for images. 
3. vex8s-controller generates a VEX document when a new pod is scheduled on the cluster, analyzing both `SecurityContext` and `VulnerabilityReport`.
4. vex8s-controller serves the VEX documents through an internal VEX Hub repository.
5. the user configures a [`VEXHub`](./examples/vexhub.yaml) CRD to point to that VEX Hub repository.

The objective is to build a kubernetes controller that leverages the [vex8s](https://github.com/alegrey91/vex8s) mitigation rules engine to generate VEX documents and serve them through an internal VEX Hub repository within the cluster. sbomscanner can then be configured to consume higly tailored VEX data directly from this in-cluster repository managed by vex8s-controller.

## Installation

To install the controller, ensure you have a running instance of kubernetes with sbomscanner installed, then use the following steps:

```
# build the docker image specifying a version:
make docker-build IMG=v0.0.1
# deploy vex8s-controller on the cluster:
make deploy IMG=v0.0.1
```

## Demo

Assuming you already have sbomscanner installed:

```
# configure sbomscanner to scan your registry
# (example file should probably be changed accordingly):
kubectl apply -f examples/registry.yaml
# wait for a vulnerabilityreport to be generated after the scan:
watch kubectl get vulnerabilityreports
# check the summary report
# (change the item ID if you have more than one vulnerabilityreport):
kubectl get vulnerabilityreport -o yaml -o=jsonpath='{.items[0].report.summary}' | jq
```

To watch it in action:

```
# run one of the images hosted in the registry previously configured:
kubectl apply -f examples/nginx.yaml
# configure sbomscanner to use the internal VEX Hub repository:
kubectl apply -f examples/vexhub.yaml
# trigger a new scan:
kubectl apply -f examples/scanjob.yaml
# check the updated vulnerabilityreport with suppressed CVEs (if any):
kubectl get vulnerabilityreport -o yaml -o=jsonpath='{.items[0].report.summary}' | jq
```

## Resources

* [vex8s](github.com/alegrey91/vex8s)
* [sbomscanner](github.com/kubewarden/sbomscanner)
