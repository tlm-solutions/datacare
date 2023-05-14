{ buildPackage, src, lib, pkg-config, cmake, protobuf, postgresql, zlib, openssl }:

buildPackage {
  pname = "datacare";
  version = "0.2.0";

  src = ./.;

  cargoSha256 = lib.fakeSha256;

  nativeBuildInputs = [ pkg-config cmake ];
  buildInputs = [ protobuf zlib postgresql openssl ];

  meta = with lib; {
    description = "Simple rust server which manages users, stations and regions";
    homepage = "https://github.com/tlm-solutions/datacare";
  };
}
