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
production-readiness scan  --kubeconfig=/home/core/.kube/config   --context cluster-name  --area-labels=area-name --teams-labels=team --image-name-replacement='mirror.registry:5000|registry.new.url,mirror-2.registry:5000|registry.new.url'
```

### Render the presentation 

Running the previous step should have given you a mark-down file called `report-imageScan.md` that you may want to convert to PDF.
Copy the mark-down file in the `audit-report` directory to render it.
See [Render-presentation](audit-report/Readme.md#Render-presentation)
```
cp report-imageScan.md audit-report/report.md
```