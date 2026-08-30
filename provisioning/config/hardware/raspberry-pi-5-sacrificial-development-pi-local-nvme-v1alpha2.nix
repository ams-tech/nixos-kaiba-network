{
  schemaVersion = "kaiba.provisioning.hardware-configuration/v1alpha2";
  configurationID = "hardware-configuration:rpi5-sacrificial-development-pi-local-nvme:1";

  executionHost.hostname = "kaiba-rpi5-provisioner";

  # This selector is valid only when the media writer itself runs on the Pi or
  # an isolated Pi provisioning lane booted from a separate medium. It is not
  # safe for a writer running on malak, where this node is the system SSD.
  targetMedia = {
    devicePath = "/dev/nvme0n1";
    protectedDevicePaths = [ ];
  };
}
