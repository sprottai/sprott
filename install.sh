#!/bin/sh
# Sprott CLI installer: github.com/sprottai/sprott (open source).
#
# What it does, in order (read it before you run it):
#   * Downloads the prebuilt `sprott` binary for this platform from the
#     project's GitHub Releases (the latest release, or SPROTT_VERSION).
#   * Verifies it against the release's SHA256SUMS and refuses to install on any
#     mismatch or missing checksum.
#   * Installs it to ~/.local/bin (or SPROTT_BIN_DIR) as `sprott`, with `sc`
#     and `safeclaw` as links to it. No sudo, no shell config changes, no
#     telemetry.
#   * Installs the Sprott agent skill with `sprott skill install` (skip with
#     --no-skill or SPROTT_NO_SKILL=1). On a machine set up before 2.0, that
#     first command moves ~/.safeclaw to ~/.sprott and restarts the daemon.
#   * When an AI agent runs it, continues with `sprott setup`; skip this with
#     SPROTT_NO_SETUP=1. Otherwise, prints one next step.
set -eu

REPO="sprottai/sprott"
if [ -n "${SPROTT_VERSION:-}" ]; then
  BASE="https://github.com/${REPO}/releases/download/${SPROTT_VERSION}"
  RELEASE="${SPROTT_VERSION}"
else
  BASE="https://github.com/${REPO}/releases/latest/download"
  RELEASE="latest release"
fi

NO_SKILL="${SPROTT_NO_SKILL:-0}"
for ARG in "$@"; do
  case "${ARG}" in
    --no-skill) NO_SKILL=1 ;;
    *) echo "Unknown argument: ${ARG}" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}/${ARCH}" in
  Linux/x86_64)   ASSET="sprott-linux-x86_64" ;;
  Linux/aarch64)  ASSET="sprott-linux-aarch64" ;;
  Darwin/x86_64)  ASSET="sprott-macos-x86_64" ;;
  Darwin/arm64)   ASSET="sprott-macos-aarch64" ;;
  *) echo "Unsupported platform: ${OS}/${ARCH}" >&2; exit 1 ;;
esac

DEST="${SPROTT_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "${DEST}"
DOWNLOAD="${DEST}/.sprott-download.$$"
trap 'rm -f "${DOWNLOAD}"' EXIT HUP INT TERM

echo "Downloading ${ASSET} from ${REPO} (${RELEASE})..."
curl -fsSL "${BASE}/${ASSET}" -o "${DOWNLOAD}"

# Integrity check against the release's published checksums.
if ! SUMS="$(curl -fsSL "${BASE}/SHA256SUMS")"; then
  echo "Could not fetch SHA256SUMS; refusing to install." >&2
  exit 1
fi
EXPECTED="$(printf '%s\n' "${SUMS}" | awk -v asset="${ASSET}" '$2 == asset { print $1; exit }')"
if [ -z "${EXPECTED}" ]; then
  echo "SHA256SUMS has no checksum for ${ASSET}; refusing to install." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${DOWNLOAD}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${DOWNLOAD}" | awk '{print $1}')"
else
  echo "No sha256sum or shasum command is available; refusing to install." >&2
  exit 1
fi
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
  echo "Checksum mismatch; refusing to install." >&2
  echo "  expected ${EXPECTED}" >&2
  echo "  got      ${ACTUAL}" >&2
  exit 1
fi
echo "Checksum OK."

chmod +x "${DOWNLOAD}"
# `sprott` is the file; `sc` and `safeclaw` link to it, so an upgrade through
# any name replaces the one file. Before 2.0 the file was `sc` (with `sprott`
# a link to it): the link replaces it, and a running 1.x daemon keeps its open
# copy until the move stops it. A `safeclaw` that is not a link is left alone.
mv "${DOWNLOAD}" "${DEST}/sprott"
trap - EXIT HUP INT TERM
ln -sf sprott "${DEST}/sc"
if [ ! -e "${DEST}/safeclaw" ] || [ -L "${DEST}/safeclaw" ]; then
  ln -sf sprott "${DEST}/safeclaw"
fi

if [ "${NO_SKILL}" != "1" ]; then
  if "${DEST}/sprott" skill --help >/dev/null 2>&1; then
    if ! "${DEST}/sprott" skill install; then
      echo "Warning: Sprott was installed, but the agent skill could not be installed." >&2
    fi
  fi
fi

echo "Installed: ${DEST}/sprott"
case ":${PATH}:" in
  *":${DEST}:"*) ;;
  *) echo "Add it to PATH: export PATH=\"${DEST}:\$PATH\"" ;;
esac
if [ "${SPROTT_CHANNEL:-}" = "dev" ]; then
  PROFILE_ARG=" --profile dev"
else
  PROFILE_ARG=""
fi
if [ "${SPROTT_NO_SETUP:-0}" != "1" ] &&
  "${DEST}/sprott" setup --detect-agent >/dev/null 2>&1; then
  echo "Setting up Sprott for this agent:"
  exec "${DEST}/sprott" setup${PROFILE_ARG}
fi
echo "Next: sprott setup --name <a name for this agent>${PROFILE_ARG}"
