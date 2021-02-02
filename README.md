# Production readiness

This tool will help running diagnostic to have a better understanding of a cluster in term of security and best practises.

## Overview

## Build, run, test

First, setup your local golang workspace by running `make setup`.

To see the full list of available flags on the app run `production-readiness --help`

### Build

Run `make install`

Note: this will also run unit tests.

### Test

#### Unit tests

For unit tests only: `make test`. 

However, it is recommended during development to call instead `make install` as this will also run linting, 
static code analysis and will check formatting.

Run `make format` to fix any formatting errors.

#### Functional tests

`make functional-test`

You may need to run `make docker` beforehand to ensure your local changes have been built and pushed to the registry.

#### Integrated tests

`make integrated-test`

You may need to run `make docker` beforehand to ensure your local changes have been built and pushed to the registry.

## Releasing


## Cheatsheet

### Run images scan

```
make build && ./build/bin/production-readiness scan  --kubeconfig=/home/core/.kube/config   --context cluster-name  --area-labels=area-name --teams-labels=team --image-name-replacement='mirror.registry:5000|registry.mew.url,mirror-2.registry:5000|registry.mew.url'  2>&1 | tee  output-save ; cp report-imageScan.md audit-report/report.md
```

### Export presentation as pdf 

```
decktape -s 1920x1080 "http://172.16.0.2:8080/?print" report-scan-images-cluster-name.pdf 
```

