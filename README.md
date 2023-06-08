# Production readiness

This tool will help running diagnostic to have a better understanding of a cluster in term of security and best practises.

## Requirements

Installed [nix](https://nixos.org/download.html)
After installation just run `nix-shell` from project directory and all required tools will be fetched.

Cluster admin privileges for security compliance scan (trivy needs to create `trivy-tmp` namespace just for testing purposes)

## Cluster scan

The `report` command can be used to perform container image and security compliance scans.
It will generate an `HTML` report for all types of scans. Summary report can be opened by opening `index.html` in the browser.

### Usage 

`production-readiness report  --context "sandbox-azure"`
`--context` points to context to use from kube config file.

## Container Image scanning

The `scan` command can be used to scan your container images for vulnerabilities.
It will look up running containers in all namespaces that matches an optional label selector (`--filters-labels`)
and perform a vulnerability scan against using [trivy](https://github.com/aquasecurity/trivy) for each container image.
It will then generate an `HTML` or `Markdown` report summarising the vulnerabilities found, their severity, CVE reference
and how many containers are affected.

It can also provide a break down of the vulnerabilities per area (`--area-labels`) / team (`--teams-labels`) when specified.

Here is a sample report:
![Sample Report](sample-report-extract.png)

### Usage

To prepare your environment you must install [trivy](https://github.com/aquasecurity/trivy) and `docker`
as the image scan utility require both command line tools.

```
production-readiness scan --context cluster-name --area-labels=area-name --teams-labels=team --image-name-replacement='mirror.registry:5000|registry.new.url,mirror-2.registry:5000|registry.new.url'
```

Run `production-readiness scan --help` for a complete list of options available.


### Rendering the report as HTML, Mark-down or PDF

The vulnerability report can be rendered using the template of your choice.
There are two available templates for convenience:
- `html`: [report-image-scan.html.tmpl](./report-image-scan.html.tmpl)
- `markdown`: [report-image-scan.md.tmpl](./report-image-scan.md.tmpl)

A custom template file can be specified using the `--report-template-filename` command line argument.

HTML files can be converted to PDF files in various ways.
One tool that works for us is [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html) which can be use as follows:
```
wkhtmltopdf <report.html> <report.pdf>
```

## Cluster security compliance scanning

The `cis-scan` command can be used to scan compliance of the cluster with the k8s CIS benchmark, NSA k8s Hardening Guidance and Pod Security Standards (PSS).
It will perform a compliance scan against using [trivy](https://github.com/aquasecurity/trivy) for whole kubernetes cluster.
Then it will generate an `HTML` report and will show which criteria has been passed and which failed.
Report allows to see vulnerable resources, their severity, description, suggested resolution and references.

Here is a sample report:
![Sample Report](sample-CIS-report.png)


### Usage

To run compliance scan just execute: `production-readiness cis-scan --context "sandbox-azure"` 
`--context` points to context to use from kube config file.
Optional parameter `--benchmarks k8s-cis,k8s-nsa,k8s-pss-restricted` can be used to run specific scan type.


## Known bugs

- Security compliance scans may not work on GCP if there is no CNI on the node in `/opt/cni/bin` location  


### TODOs

- Fix tests configuration as some of the tests are throwing `You may only call BeforeEach from within a Describe, Context or When`  
- use trivy library rather than the command line
- use docker library rather than the command line
- releasing


## Linuxbench

_This is work in progress_

