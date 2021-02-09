# Image Scanning
<!-- .element: class="title-first-page" -->
<!-- .slide: data-background-image="../../assets/images/deck-title-page-big.jpg" -->


### Image scan summary 
<!-- .element: class="title-detailed-page" -->
<div style="display: inline-block; text-align: left;">

Images scanned running in your cluster: 2

Pods scanned running in your cluster: 3

Images coming from external registries: 0

Images with vulnerability: 0
</div>

| Registry | Images Count | Pod Count |
|----------|-------------:|----------:|
<!-- .element: class="table-report-medium" -->

| Type | Vulnerabilities |
|------|----------------:|
| CRITICAL | 0 |
| HIGH | 0 |
| LOW | 0 |
| MEDIUM | 1 |
| UNKNOWN | 0 |
<!-- .element: class="table-report-medium" -->


### Image best pratices
<!-- .element: class="title-detailed-page" -->
<div style="display: inline-block; text-align: left;">

These images are exposed to an outage from this external source

They can hit a rate limit from this provider 

Using only internal registry allow you to:

- block the promotion in your cluster if vulnerabilities have been found

- block external image deployment with an admission controller
</div>


### Top 20 images containing the most vulnerabilities 
<!-- .element: class="title-detailed-page" -->

| Image | Replicas | Critical| High | Medium | Low |
|-------|----------|---------|------|--------|-----|
<!-- .element: class="table-report-medium" -->


### Top 20 images containing vulnerabilities with the most replicas 
<!-- .element: class="title-detailed-page" -->

| Image | Replicas | Critical| High | Medium | Low |
|-------|----------|---------|------|--------|-----|
<!-- .element: class="table-report-medium" -->


### Image scan summary - area-1 - team-1
<!-- .element: class="title-detailed-page" -->
<div style="display: inline-block; text-align: left;">

Images scanned running in your cluster: 2

Pods scanned running in your cluster: 3

Images coming from external registries: 0

Images with vulnerability: 0
</div>

| Registry | Images Count | Pod Count |
|----------|-------------:|----------:|
<!-- .element: class="table-report-medium" -->

| Type | Vulnerabilities |
|------|----------------:|
| CRITICAL | 0 |
| HIGH | 0 |
| LOW | 0 |
| MEDIUM | 1 |
| UNKNOWN | 0 |
<!-- .element: class="table-report-medium" -->
### Vulnerabilities - area-1 - team-1
<!-- .element: class="title-detailed-page" -->
#### Vulnerabilities - area-1 - team-1 - part 1

| Image | CVE | Severity | PkgName | Description |
|-------|-----|----------|---------|-------------|
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
<!-- .element: class="table-report" -->
<!-- .element: class="title-detailed-page" -->
#### Vulnerabilities - area-1 - team-1 - part 2

| Image | CVE | Severity | PkgName | Description |
|-------|-----|----------|---------|-------------|
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| ubuntu:18.04 | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| ubuntu:18.04 | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
<!-- .element: class="table-report" -->


### Image scan summary - area-1 - team-2
<!-- .element: class="title-detailed-page" -->
<div style="display: inline-block; text-align: left;">

Images scanned running in your cluster: 1

Pods scanned running in your cluster: 1

Images coming from external registries: 0

Images with vulnerability: 0
</div>

| Registry | Images Count | Pod Count |
|----------|-------------:|----------:|
<!-- .element: class="table-report-medium" -->

| Type | Vulnerabilities |
|------|----------------:|
| CRITICAL | 2 |
| HIGH | 10 |
| LOW | 0 |
| MEDIUM | 1 |
| UNKNOWN | 0 |
<!-- .element: class="table-report-medium" -->
### Vulnerabilities - area-1 - team-2
<!-- .element: class="title-detailed-page" -->

| Image | CVE | Severity | PkgName | Description |
|-------|-----|----------|---------|-------------|
| ubuntu:18.04 | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| ubuntu:18.04 | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| ubuntu:18.04 | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| ubuntu:18.04 | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
<!-- .element: class="table-report" -->


### Image scan summary - area-2 - team-3
<!-- .element: class="title-detailed-page" -->
<div style="display: inline-block; text-align: left;">

Images scanned running in your cluster: 1

Pods scanned running in your cluster: 4

Images coming from external registries: 0

Images with vulnerability: 0
</div>

| Registry | Images Count | Pod Count |
|----------|-------------:|----------:|
<!-- .element: class="table-report-medium" -->

| Type | Vulnerabilities |
|------|----------------:|
| CRITICAL | 3 |
| HIGH | 2 |
| LOW | 0 |
| MEDIUM | 10 |
| UNKNOWN | 0 |
<!-- .element: class="table-report-medium" -->
### Vulnerabilities - area-2 - team-3
<!-- .element: class="title-detailed-page" -->
#### Vulnerabilities - area-2 - team-3 - part 1

| Image | CVE | Severity | PkgName | Description |
|-------|-----|----------|---------|-------------|
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2021-3326](https://nvd.nist.gov/vuln/detail/CVE-2021-3326) | HIGH | libc-bin | glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2020-13844](https://nvd.nist.gov/vuln/detail/CVE-2020-13844) | MEDIUM | libstdc&#43;&#43;6 | kernel: ARM straight-line speculation vulnerability |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
<!-- .element: class="table-report" -->
<!-- .element: class="title-detailed-page" -->
#### Vulnerabilities - area-2 - team-3 - part 2

| Image | CVE | Severity | PkgName | Description |
|-------|-----|----------|---------|-------------|
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
| debian:latest | [CVE-2011-3374](https://nvd.nist.gov/vuln/detail/CVE-2011-3374) | LOW | apt | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyrin... |
<!-- .element: class="table-report" -->