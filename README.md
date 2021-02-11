# Production readiness

This tool will help running diagnostic to have a better understanding of a cluster in term of security and best practises.

## Overview

## Build, run, test

First, setup your local golang workspace by running `make setup`.

To see the full list of available flags on the app run `production-readiness --help`

### Build

Run `make install`

Note: this will also run unit tests.

### Testing

#### Unit tests

For unit tests only: `make test`. 

However, it is recommended during development to call instead `make install` as this will also run linting, 
static code analysis and will check formatting.

Run `make format` to fix any formatting errors.

#### Integrated tests

Integrated tests will run an image scan against a local [Kind](https://kind.sigs.k8s.io/) cluster.
To prepare your environment you must install [trivy](https://github.com/aquasecurity/trivy) and `docker`

To create a [Kind](https://kind.sigs.k8s.io/) Kubernetes cluster:
```
make kind
```

To run the integrated tests:
```
make integrated-test
```

## Releasing

_To be defined_


## Cheatsheet

### Run images scan

To prepare your environment you must install [trivy](https://github.com/aquasecurity/trivy) and `docker`
as the image scan utility require both command line tools.

```
production-readiness scan  --context cluster-name  --area-labels=area-name --teams-labels=team --image-name-replacement='mirror.registry:5000|registry.new.url,mirror-2.registry:5000|registry.new.url'
```

### Render the presentation 

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

## TODOs

- use trivy library rather than the command line
- use docker library rather than the command line
- change the scan template to support (again) pagination
- restructure the code for better encapsulation
- releasing