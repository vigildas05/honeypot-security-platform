export function guessCountry(ip) {
  if (!ip || ip === "127.0.0.1" || ip === "::1" || ip.startsWith("192.168.")) {
    return "Local";
  }

  return "Unknown";
}
