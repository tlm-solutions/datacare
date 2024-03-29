{ inputs, modulesPath, ... }:
{
  imports = [
    "${modulesPath}/virtualisation/qemu-vm.nix"
    ./postgres.nix
    ./datacare.nix
  ];

  fileSystems = {
    "/" = {
      device = "/dev/disk/by-label/nixos";
      fsType = "ext4";
    };
  };

  boot = {
    kernelParams = [ "console=ttyS0" "boot.shell_on_fail" ];
    loader.timeout = 5;
  };

  virtualisation = {
    diskSize = 512;
    memorySize = 512;
    graphics = false;
  };

  services.getty = {
    autologinUser = "root";
  };
  users.motd = ''
    Datacare-McTest: enterprise-grade, free-range, grass-fed testing vm
    Now with 100% less graphics!

    Services exposed to the host:
    datacare: 8070
    SSH: 2223
    postgres: 8889
    redis: 8062

    root password is "lol"

    have fun!
  '';


  networking.firewall.enable = false;

  users.mutableUsers = false;
  users.users.root.password = "lol";
  services.openssh = {
    enable = true;
    permitRootLogin = "yes";
  };

  system.stateVersion = "22.11";
}
