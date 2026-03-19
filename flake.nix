# Install via:
# nix profile add .#wireguard-go
{
  description = "wireguard-go (incl. DNS resolve on re-connect patch)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs, ... }:
  let
    supportedSystems = [ "aarch64-darwin" ];

    forAllSystems = f:
      nixpkgs.lib.genAttrs supportedSystems (system:
        f system
      );
  in
  {
    packages = forAllSystems (system:
      let
        pkgs = import nixpkgs { inherit system; };
        wireguard-go = pkgs.buildGoModule {
          pname = "wireguard-go";
          version = "0.0.20250522";
          src = ./.;
          doCheck = false; # Some vendor packages don't have properly formatted code
          vendorHash = "sha256-sCajxTV26jjlmgmbV4GG6hg9NkLGS773ZbFyKucvuBE=";
        };
      in {
        default = wireguard-go;
        wireguard-go = wireguard-go;
      }
    );

    apps = forAllSystems (system:
      let
        pkg = self.packages.${system}.default;
      in {
        default = {
          type = "app";
          program = "${pkg}/bin/wireguard-go";
        };
      }
    );
  };
}
