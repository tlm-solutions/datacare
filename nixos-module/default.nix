{ pkgs, config, lib, ... }:
let
  cfg = config.TLMS.datacare;
in
{
  options.TLMS.datacare = with lib; {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Wether to enable datacare: TLMS colorful and clicky registration tool
      '';
    };
    rustBacktrace = mkOption {
      type = types.str;
      default = "FULL";
      description = ''rust backtrace'';
    };

    saltFile = mkOption {
      type = types.either types.str types.path;
      default = "";
      description = ''file from where the salt can be read'';
    };

    allowedIpsExport = mkOption {
      type = types.listOf types.string;
      default = [];
      description = ''List of Ip Prefixes that should have access to the export endpoint'';
    };

    http = {
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = ''host of datacare'';
      };
      port = mkOption {
        type = types.port;
        default = 5070;
        description = ''port of datacare'';
      };
    };
    
    database = {
      passwordFile = mkOption {
        type = types.either types.str types.path;
        default = "";
        description = ''file from where the postgres password can be read'';
      };
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = ''file from where the postgres password can be read'';
      };
      port = mkOption {
        type = types.int;
        default = 5070;
        description = ''port of the postgres database'';
      };
      user = mkOption {
        type = types.str;
        default = "datacare";
        description = ''user of the postgres database'';
      };
      database = mkOption {
        type = types.str;
        default = "tlms";
        description = ''postgres database that should be used'';
      };
    };

    user = mkOption {
      type = types.str;
      default = "datacare";
      description = ''systemd user'';
    };
    group = mkOption {
      type = types.str;
      default = "datacare";
      description = ''group of systemd user'';
    };
    cookieDomain = mkOption {
      type = types.str;
      default = "tlm.solutions";
      description = ''domain of the api'';
    };
    log_level = mkOption {
      # TODO: make an enum of possible values
      type = types.str;
      # this is a little weird because if want to see all the correct value would be trace
      default = "datacare";
      description = ''log level of the application'';
    };
    redis = {
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = ''Host on which redis is listening'';
      };
      port = mkOption {
        type = types.port;
        default = 6379;
        description = ''Redis port'';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.datacare ];
    systemd.services = {
      "datacare" = {
        enable = true;

        description = "tlms managment service";
        wantedBy = [ "multi-user.target" ];

        script = ''
          exec ${pkgs.datacare}/bin/datacare --host ${cfg.http.host} --port ${toString cfg.http.port}&
        '';

        environment = {
          "RUST_BACKTRACE" = "${cfg.rustBacktrace}";
          "SALT_PATH" = "${cfg.saltFile}";
          "RUST_LOG" = "${cfg.log_level}";
          "DATACARE_POSTGRES_HOST" = "${cfg.database.host}";
          "DATACARE_POSTGRES_PORT" = "${toString cfg.database.port}";
          "DATACARE_POSTGRES_USER" = "${toString cfg.database.user}";
          "DATACARE_POSTGRES_DATABASE" = "${toString cfg.database.database}";
          "DATACARE_POSTGRES_PASSWORD_PATH" = "${cfg.database.passwordFile}";
          "DATACARE_REDIS_HOST" = "${cfg.redis.host}";
          "DATACARE_REDIS_PORT" = "${toString cfg.redis.port}";
          "DATACARE_COOKIE_DOMAIN" = "${cfg.cookieDomain}";
          "DATACARE_PROMETHEUS_ALLOWED_IPS" = "${builtins.toJSON cfg.allowedIpsExport}";
        };

        serviceConfig = {
          Type = "forking";
          User = "datacare";
          Restart = "always";
        };
      };
    };

    # user accounts for systemd units
    users.users."${cfg.user}" = {
      name = cfg.user;
      isSystemUser = true;
      group = cfg.group;
    };
  };
}
