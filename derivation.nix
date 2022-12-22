{ naersk, src, lib, pkg-config, cmake, protobuf, postgresql, zlib }:

naersk.buildPackage {
  pname = "datacare";
  version = "0.1.0";

  src = ./.;

  cargoSha256 = lib.fakeSha256;

  nativeBuildInputs = [ pkg-config cmake ];
  buildInputs = [ protobuf zlib postgresql ];

  meta = with lib; {
    description = "Simple rust server which manages users, stations and regions";
    homepage = "https://github.com/dump-dvb/datacare";
  };
}
