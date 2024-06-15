# SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
# SPDX-License-Identifier: Apache-2.0
{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShell = pkgs.mkShell {
          buildInputs = with pkgs;
            [
              go
              golangci-lint
              reuse
            ];

            packages = with pkgs; [
              rosenpass
            ];
        };

        formatter = nixpkgs.nixfmt-rfc-style;
      }
    );
}
