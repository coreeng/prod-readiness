with (import (fetchTarball https://github.com/nixos/nixpkgs/archive/9c8ff8b426a8b07b9e0a131ac3218740dc85ba1e.tar.gz) {});
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
  ];

  shellHook = ''
    export GOROOT=""
    export GOPATH=""
  '';
}