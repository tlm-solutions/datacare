{ config, ... }: {
  TLMS.datacare = {
    enable = true;
    http = {
      host = "0.0.0.0";
      port = 8070;
    };
    database = {
      host = "127.0.0.1";
      port = config.services.postgresql.port;
      user = "tlms";
      database = "tlms";
      passwordFile = ./test-pw;
    };
    saltFile = ./test-salt;
    user = "datacare";
  };
  systemd.services."datacare" = {
    after = [ "postgresql.service" ];
    wants = [ "postgresql.service" ];
  };

  services.redis.servers."datacare" = {
    enable = true;
    bind = config.TLMS.datacare.redis.host;
    port = config.TLMS.datacare.redis.port;
  };
}
