{
  description = "A better WHOIS lookup tool";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages = rec {
          default = quien;
          quien = pkgs.callPackage (
            {buildGoModule}:
              buildGoModule (finalAttrs: {
                pname = "quien";
                version = "0.8.1";
                vendorHash = "sha256-/uizVtnbjkm4CTVxLECFeqBsBEue5vb7QALA+RbLmSc=";
                src = ./.;

                env.CGO_ENABLED = 0;
                ldflags = [
                  "-s"
                  "-w"
                  "-X main.version=${finalAttrs.version}"
                ];
              })
          ) {};
        };

        apps = rec {
          default = quien;
          quien = flake-utils.lib.mkApp {drv = self.packages.${system}.quien;};
        };
      }
    );
}
