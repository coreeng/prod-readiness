# Contributing

Contributions are welcomed!

When contributing to this repository, please first discuss the change you wish to make via a GitHub
issue before making a change.  This saves everyone from wasted effort in the event that the proposed
changes need some adjustment before they are ready for submission.
All new code, including changes to existing code, should be tested and have a corresponding test added or updated where applicable.

## Prerequisites

The following must be installed on your development machine:

- `go` (>=1.20)
- `docker`
- `kind`
- `trivy`
- `kubectl`

You can use [nix](https://nixos.org/download.html) to make install the required tools by running:
```
nix-shell
```

## Building and testing

To setup your environment with the required dependencies, run this at the project root level.
_Missing system libraries that need installing will be listed in the output_
```
make setup
```

To compile and install the binary locally
```
make install
```

To run code style checks
```
make check
```

To run unit tests only:
```
make test
```

### Integrated tests

Integrated tests will run an image scan against a local [Kind](https://kind.sigs.k8s.io/) cluster.
To prepare your environment you must install [trivy](https://github.com/aquasecurity/trivy) and [Kind](https://kind.sigs.k8s.io/).

To create a [Kind](https://kind.sigs.k8s.io/) Kubernetes cluster:
```
make kind
```

To run the integrated tests:
```
make integrated-test
```

## Releasing

Use [semantic-release](https://github.com/semantic-release/github) to automate versioning, tag and 
create GitHub releases based on the commit message.
semantic-release works from release branches, not pull requests. As a result, nothing will be released on pull requests.

Commit messages must follow [Angular Commit Message Conventions](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format)

### Initial semantic release installation

1. Make sure you're on the latest version of npm
```
npm install -g npm
```

2. Generate the `package.json`
```
npm init
```

3. Generate the `package-lock.json`
```
npm install --save-dev semantic-release
```

4. Commit both `package.json` and `package-lock.json`at the root of your repository

### Local run

Use the `dry-run` mode to check the changes `semantic-release` would perform
```sh
GITHUB_TOKEN=$(gh auth token) npx semantic-release --dry-run --branches=$(git rev-parse --abbrev-ref HEAD)
```


## Contributor Code of Conduct

As contributors and maintainers of this project, and in the interest of fostering an open and
welcoming community, we pledge to respect all people who contribute through reporting issues,
posting feature requests, updating documentation, submitting pull requests or patches, and other
activities.

We are committed to making participation in this project a harassment-free experience for everyone,
regardless of level of experience, gender, gender identity and expression, sexual orientation,
disability, personal appearance, body size, race, ethnicity, age, religion, or nationality.

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery
* Personal attacks
* Trolling or insulting/derogatory comments
* Public or private harassment
* Publishing other's private information, such as physical or electronic addresses, without explicit
  permission
* Other unethical or unprofessional conduct.

Project maintainers have the right and responsibility to remove, edit, or reject comments, commits,
code, wiki edits, issues, and other contributions that are not aligned to this Code of Conduct. By
adopting this Code of Conduct, project maintainers commit themselves to fairly and consistently
applying these principles to every aspect of managing this project. Project maintainers who do not
follow or enforce the Code of Conduct may be permanently removed from the project team.

This code of conduct applies both within project spaces and in public spaces when an individual is
representing the project or its community.

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by opening an
issue or contacting one or more of the project maintainers.

This Code of Conduct is adapted from the [Contributor Covenant](http://contributor-covenant.org),
version 1.2.0, available at
[http://contributor-covenant.org/version/1/2/0/](http://contributor-covenant.org/version/1/2/0/)
