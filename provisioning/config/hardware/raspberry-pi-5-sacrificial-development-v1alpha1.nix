{
  schemaVersion = "kaiba.provisioning.hardware-configuration/v1alpha1";
  configurationID = "hardware-configuration:rpi5-sacrificial-development:1";

  # This is station-local operational selection, not boot-media identity and
  # not a field in canonical media plans, receipts, or evidence.
  targetMedia.devicePath = "/dev/nvme0n1";
}
