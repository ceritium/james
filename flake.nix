{
  description = "james lends 1Password secrets to coding agents, approved with Touch ID";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "aarch64-darwin";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default = pkgs.callPackage ./package.nix {
        version = self.shortRev or self.dirtyShortRev or "dev";
      };
    };
}
