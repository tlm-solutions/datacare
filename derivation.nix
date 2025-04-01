{ buildPackage, lib, pkg-config, cmake, protobuf, zlib, openssl, libpq, writeScriptBin}:
let
datacare = buildPackage {
  pname = "datacare";
  version = "0.3.1";

  src = ./.;

  cargoSha256 = lib.fakeSha256;

  nativeBuildInputs = [ pkg-config cmake protobuf zlib openssl libpq ];

  preBuildHook = ''
  '';

  meta = {
    description = "Simple rust server which manages users, stations and regions";
    homepage = "https://github.com/tlm-solutions/datacare";
  };
};
in 
(
  writeScriptBin "datacare" ''
    export LD_LIBRARY_PATH=${libpq}/lib:$LD_LIBRARY_PATH
    ${datacare}/bin/datacare $@
  ''
)
