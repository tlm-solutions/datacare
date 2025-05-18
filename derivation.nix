{ buildPackage, stdenv, lib, pkg-config, cmake, protobuf, zlib, openssl, postgresql }:

let
  datacare = buildPackage {
    pname = "datacare";
    version = "0.3.1";

    src = ./.;

    cargoSha256 = lib.fakeSha256;

    nativeBuildInputs = [ pkg-config cmake ];
    buildInputs = [ protobuf zlib openssl postgresql ];

    meta = {
      description = "Simple rust server which manages users, stations and regions";
      homepage = "https://github.com/tlm-solutions/datacare";
    };
  };
in
stdenv.mkDerivation {
  name = "datacare-patchelf";
  src = datacare;

  buildPhase = "";

  installPhase = ''
    mkdir -p $out/bin
    cp $src/bin/datacare $out/bin/datacare
    chmod +w $out/bin/datacare
  
    patchelf --replace-needed libpq.so.5 ${postgresql.lib}/lib/libpq.so $out/bin/datacare

    # check if the patch succeded and exit if a depedency is not found
    local patch_succeded

    patch_succeded=$(ldd $out/bin/datacare | grep "not found" | wc -l || true)
    if [[ "$patch_succeded" -ne 0 ]]; then
      echo "Patching failed" && exit 1
    fi
  '';
}