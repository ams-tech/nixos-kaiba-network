{
  schemaVersion = "kaiba.provisioning.hardware-configuration/v1alpha2";
  configurationID = "hardware-configuration:malak-rpi5-sacrificial-development-usb-sd:1";

  executionHost.hostname = "malak";

  # This binds malak's observed USB reader topology and port, not SD-card
  # identity. Moving the reader to another port must fail closed. The protected
  # path is an independent hard stop if this selector ever resolves to malak's
  # system SSD.
  targetMedia = {
    devicePath = "/dev/disk/by-path/pci-0000:0e:00.3-usb-0:4:1.0-scsi-0:0:0:0";
    protectedDevicePaths = [ "/dev/nvme0n1" ];
  };
}
