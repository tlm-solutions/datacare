{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    utils = {
      url = "github:numtide/flake-utils";
    };

    tlms-rs = {
      url = "github:tlm-solutions/tlms.rs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      #inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self
    , tlms-rs
    , nixpkgs
    , naersk
    , utils
    , fenix
    , ...
    }:
    utils.lib.eachDefaultSystem
      (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        toolchain = with fenix.packages.${system}; combine [
          latest.cargo
          latest.rustc
        ];

        package = pkgs.callPackage ./derivation.nix {
          buildPackage = (naersk.lib.${system}.override {
            cargo = toolchain;
            rustc = toolchain;
          }).buildPackage;
        };

        test-vm-pkg = self.nixosConfigurations.datacare-mctest.config.system.build.vm;
      in
      rec {
        checks = packages;
        packages = {
          datacare = package;
          default = package;
          test-vm = test-vm-pkg;
          test-vm-wrapper = pkgs.writeScript "datacare-test-vm-wrapper"
            ''
              set -e
              echo Datacare-McTest: enterprise-grade, free-range, grass-fed testing vm
              echo "ALL RELEVANT SERVICES WILL BE EXPOSED TO THE HOST:"
              echo -e "Service\t\tPort"
              echo -e "SSH:\t\t2223\troot:lol"
              echo -e "postgres:\t8889"
              echo -e "datacare:\t8070"
              echo -e "redis:\t\t8062"
              echo

              set -x
              export QEMU_NET_OPTS="hostfwd=tcp::2223-:22,hostfwd=tcp::8889-:5432,hostfwd=tcp::8070-:8070,hostfwd=tcp::8062-:6379"
              echo "running the vm now..."
              ${self.packages.${system}.test-vm}/bin/run-nixos-vm
            '';
        };
        apps = {
          mctest = {
            type = "app";
            program = "${self.packages.${system}.test-vm-wrapper}";
          };
        };
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = (with packages.datacare; nativeBuildInputs ++ buildInputs);
        };
      }
      ) // {
      overlays.default = final: prev: {
        inherit (self.packages.${prev.system})
          datacare;
      };
      nixosModules = rec {
        default = datacare;
        datacare = import ./nixos-module;
      };

      nixosConfigurations.datacare-mctest = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        specialArgs = { inherit inputs; };
        modules = [
          self.nixosModules.default
          ./tests/vm
          {
            nixpkgs.overlays = [
              self.overlays.default
            ];
          }
        ];
      };


      hydraJobs =
        let
          hydraSystems = [
            "x86_64-linux"
            "aarch64-linux"
          ];
        in
        builtins.foldl'
          (hydraJobs: system:
            builtins.foldl'
              (hydraJobs: pkgName:
                nixpkgs.lib.recursiveUpdate hydraJobs {
                  ${pkgName}.${system} = self.packages.${system}.${pkgName};
                }
              )
              hydraJobs
              (builtins.attrNames self.packages.${system})
          )
          { }
          hydraSystems;
    };
}
