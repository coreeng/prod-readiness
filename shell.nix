with (import (fetchTarball https://github.com/nixos/nixpkgs/archive/3a70dd92993182f8e514700ccf5b1ae9fc8a3b8d.tar.gz) {});
mkShell {
  buildInputs = [
    go
    gotools
    golint
    trivy
    docker
    azure-cli
    kubelogin
    kubectl
    kind
  ];

}