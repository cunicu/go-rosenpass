# SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
# SPDX-License-Identifier: Apache-2.0
{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlay = final: prev: { go-rosenpass = final.callPackage ./default.nix { }; };

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ overlay ];
        };
      in
      {
        packages.default = pkgs.go-rosenpass;
        overlays.default = overlay;

        devShell = pkgs.mkShell {
          inputsFrom = with pkgs; [ go-rosenpass ];

          buildInputs = with pkgs; [
            golangci-lint
            reuse
          ];
        };

        formatter = nixpkgs.nixfmt-rfc-style;
      }
    );
}
