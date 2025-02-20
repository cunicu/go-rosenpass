# SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
# SPDX-License-Identifier: Apache-2.0
{
  buildGoModule,
  lib,
  rosenpass,
  ...
}:
buildGoModule {
  pname = "go-rosenpass";
  version = "0.4.0";
  src = ./.;
  vendorHash = "sha256-VT5lDrrhG75ydnYZ93Y/Z0qIcAEsSxdVfq2DqSQP4Uc=";

  subPackages = [ "cmd" ];

  env.CGO_ENABLED = 0;

  nativeCheckInputs = [ rosenpass ];

  postInstall = ''
    mv $out/bin/cmd $out/bin/go-rosenpass
  '';

  meta = {
    description = "A port of Rosenpass post-quantum key-exchange protocol to Go.";
    homepage = "https://github.com/cunicu/go-rosenpass";
    license = lib.licenses.asl20;
    maintainers = with lib.maintainers; [ stv0g ];
  };
}
