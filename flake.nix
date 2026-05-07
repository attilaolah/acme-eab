{
  description = "Smallstep ACME EAB helper";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {nixpkgs, ...}: let
    inherit (nixpkgs) lib;

    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-darwin"
      "x86_64-linux"
    ];

    forAllSystems = lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      pkgs = import nixpkgs {inherit system;};
    in rec {
      acme-eab-add = pkgs.buildGoModule {
        pname = "acme-eab-add";
        version = "0.1.0";

        src = ./.;
        vendorHash = "sha256-gMwKX6rwKia4+hhbMJrJLhXidT47JGsd0//fyBemRVA=";

        subPackages = ["cmd/acme-eab-add"];

        meta = {
          description = "Write Smallstep ACME External Account Binding credentials into the Step CA database";
          homepage = "https://github.com/attilaolah/acme-eab";
          license = lib.licenses.mit;
          mainProgram = "acme-eab-add";
        };
      };

      default = acme-eab-add;
    });

    devShells = forAllSystems (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          go
          gopls
        ];
      };
    });
  };
}
