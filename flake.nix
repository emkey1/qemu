# SPDX-License-Identifier: GPL-2.0-or-later
#
# The shells the fork is built and tested in: `nix develop` to build QEMU, and
# `nix develop .#tests` to run check-tcg as the CI does. tctiSH's flake calls
# these outputs with its own nixpkgs, for its builds of QEMU for the Mac, so
# they must take nothing but nixpkgs.
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      # TCTI needs an AArch64 host, and the fork is built on Apple silicon.
      system = "aarch64-darwin";
      pkgs = nixpkgs.legacyPackages.${system};

      # A bare-metal gcc for the TCG system tests, run with none of the shell's
      # NIX_ variables. nix's cc-wrapper applies those to every compiler on the
      # path, cross ones included, and here they are the host's: its include
      # paths, -lintl and its hardening flags, none of which a bare-metal target
      # has.
      bareMetalGcc =
        cross: prefix:
        pkgs.writeShellScriptBin "${prefix}-gcc" ''
          unset "''${!NIX_@}"
          exec ${cross.buildPackages.gcc}/bin/${prefix}-gcc "$@"
        '';
    in
    {
      devShells.${system} = rec {
        # Building QEMU: everything nixpkgs builds its QEMU with, of which
        # configure uses what its flags ask for.
        default = pkgs.mkShell {
          inputsFrom = [ pkgs.qemu ];
          packages = [ pkgs.git ];
        };

        # Building QEMU and running check-tcg for x86_64 and AArch64 guests.
        tests = pkgs.mkShell {
          inputsFrom = [ default ];
          packages = [
            (bareMetalGcc pkgs.pkgsCross.x86_64-embedded "x86_64-elf")
            (bareMetalGcc pkgs.pkgsCross.aarch64-embedded "aarch64-none-elf")
          ];
        };
      };
    };
}
