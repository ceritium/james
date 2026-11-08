{
  lib,
  buildGoModule,
  apple-sdk_15,
  version ? "dev",
}:

buildGoModule {
  pname = "james";
  inherit version;
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./cmd
      ./internal
    ];
  };
  vendorHash = "sha256-o7tDxmn4fwyI7ZGxDbLF5HnGMP4JQmzeojw0qG5z8Uw=";
  subPackages = [ "cmd/james" ];
  # LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion is new in macOS 15.
  buildInputs = [ apple-sdk_15 ];
  env.CGO_ENABLED = 1;
  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];
  # The peer tests talk to real processes; run them with go test in the checkout.
  doCheck = false;

  postInstall = ''
    install -Dm444 cmd/james/skill/SKILL.md $out/share/james/skill/SKILL.md
  '';

  # Hardened runtime keeps even root from reading daemon memory. sigtool, which nixpkgs
  # signs with, cannot set it, so this needs the system codesign (sandbox off).
  postFixup = ''
    /usr/bin/codesign --force --sign - --options runtime \
      --entitlements ${./cmd/james/entitlements.plist} $out/bin/james
  '';

  meta = {
    description = "Lends 1Password secrets to coding agents, approved with Touch ID";
    platforms = lib.platforms.darwin;
    mainProgram = "james";
  };
}
