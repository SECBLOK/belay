#!/usr/bin/env bash
# Belay one-command installer.
#
#   curl -fsSL https://dl.belay.secblok.io/install.sh | bash
#
# Downloads the platform-appropriate static `belay` binary -- from the
# SECBLOK R2 CDN (dl.belay.secblok.io) when it has the asset, falling
# back to the repo's latest GitHub Release otherwise -- verifies its SHA-256
# checksum against the published SHA256SUMS, installs it, then hands off to
# the interactive `belay setup` wizard (reconnecting the terminal via
# /dev/tty, since stdin is the curl pipe under `curl | bash`).
#
# Review before you run it:
#   curl -fsSL https://dl.belay.secblok.io/install.sh -o install.sh
#   less install.sh
#   bash install.sh
#
# Flags (passed through to `belay setup` unless noted):
#   --skip-setup / --no-setup / -y   don't run the setup wizard at all
#   (any other flag)                 forwarded verbatim to `belay setup`
#
# Env overrides:
#   BELAY_DOWNLOAD_BASE  primary download host (default https://dl.belay.secblok.io);
#                             GitHub Releases is always tried as a fallback
#   BELAY_REPO           GitHub "owner/repo" for the fallback (default SECBLOK/belay)
#   BELAY_VERSION        pin a release tag instead of "latest" (forces GitHub;
#                             the R2 CDN mirrors only "latest", it has no per-version paths)
#   BELAY_INSTALL_DIR    where to place the binary (default /usr/local/bin)
#   BELAY_INSTALL_SELFTEST=1   run the built-in offline self-test instead of installing
#
# Safety: the whole script is wrapped in `main() { ... }; main "$@"` so a
# connection dropped mid-download can't half-execute a truncated script — bash
# must finish parsing the entire `main` function body before it can run the
# final `main "$@"` call, and nothing outside that call is ever a top-level
# executable statement.
set -euo pipefail

main() {
  # -----------------------------------------------------------------------
  # Self-test mode: exercise the pure OS/arch -> release-target mapping with
  # faked inputs, no network, no filesystem writes. See the bottom of this
  # function for what it asserts.
  # -----------------------------------------------------------------------
  belay_detect_target() {
    # Pure: os ("Linux"/"Darwin", i.e. `uname -s`) + arch ("x86_64"/"aarch64"/
    # "arm64", i.e. `uname -m`) -> the release asset's target triple suffix.
    # Prints the target to stdout and returns 0 on success; on an
    # unrecognized os/arch it prints an error to stderr and returns 1 --
    # NEVER silently falls back to a guess.
    local os="$1" arch="$2"
    case "$os" in
      Linux)
        case "$arch" in
          x86_64) echo "x86_64-unknown-linux-musl" ;;
          aarch64) echo "aarch64-unknown-linux-musl" ;;
          *)
            echo "belay-install: unsupported architecture '$arch' on Linux (supported: x86_64, aarch64)" >&2
            return 1
            ;;
        esac
        ;;
      Darwin)
        case "$arch" in
          x86_64) echo "x86_64-apple-darwin" ;;
          # Apple Silicon's `uname -m` reports "arm64", not "aarch64" --
          # both map to the same aarch64-apple-darwin release asset.
          aarch64 | arm64) echo "aarch64-apple-darwin" ;;
          *)
            echo "belay-install: unsupported architecture '$arch' on macOS (supported: x86_64, aarch64/arm64)" >&2
            return 1
            ;;
        esac
        ;;
      *)
        echo "belay-install: unsupported OS '$os' (supported: Linux, Darwin)" >&2
        return 1
        ;;
    esac
  }

  if [ "${BELAY_INSTALL_SELFTEST:-}" = "1" ]; then
    local selftest_fails=0
    belay_selftest_assert() {
      local desc="$1" expected="$2" actual="$3"
      if [ "$expected" = "$actual" ]; then
        echo "ok - $desc"
      else
        echo "not ok - $desc (expected '$expected', got '$actual')"
        selftest_fails=$((selftest_fails + 1))
      fi
    }

    belay_selftest_assert "linux x86_64" "x86_64-unknown-linux-musl" \
      "$(belay_detect_target Linux x86_64)"
    belay_selftest_assert "linux aarch64" "aarch64-unknown-linux-musl" \
      "$(belay_detect_target Linux aarch64)"
    belay_selftest_assert "macos x86_64" "x86_64-apple-darwin" \
      "$(belay_detect_target Darwin x86_64)"
    belay_selftest_assert "macos aarch64" "aarch64-apple-darwin" \
      "$(belay_detect_target Darwin aarch64)"
    belay_selftest_assert "macos arm64 (uname -m alias)" "aarch64-apple-darwin" \
      "$(belay_detect_target Darwin arm64)"

    if belay_detect_target Plan9 x86_64 >/dev/null 2>&1; then
      echo "not ok - unknown OS must hard-fail"
      selftest_fails=$((selftest_fails + 1))
    else
      echo "ok - unknown OS hard-fails"
    fi
    if belay_detect_target Linux riscv64 >/dev/null 2>&1; then
      echo "not ok - unknown arch must hard-fail"
      selftest_fails=$((selftest_fails + 1))
    else
      echo "ok - unknown arch hard-fails"
    fi

    if [ "$selftest_fails" -eq 0 ]; then
      echo "belay-install: selftest OK"
      return 0
    fi
    echo "belay-install: selftest FAILED ($selftest_fails check(s))"
    return 1
  fi

  # -----------------------------------------------------------------------
  # Config
  # -----------------------------------------------------------------------
  local repo="${BELAY_REPO:-SECBLOK/belay}"
  local version="${BELAY_VERSION:-}"
  local install_dir="${BELAY_INSTALL_DIR:-/usr/local/bin}"

  # Download hosts, in priority order. The SECBLOK R2 CDN
  # (BELAY_DOWNLOAD_BASE) is tried first; GitHub Releases is the fallback,
  # so platforms not (yet) mirrored to R2 -- macOS, Linux aarch64 -- still
  # install. A pinned BELAY_VERSION forces GitHub only, since R2 mirrors
  # "latest" at flat paths and has no per-version directories.
  local cdn_base="${BELAY_DOWNLOAD_BASE:-https://dl.belay.secblok.io}"
  local gh_base
  if [ -n "$version" ]; then
    gh_base="https://github.com/${repo}/releases/download/${version}"
  else
    gh_base="https://github.com/${repo}/releases/latest/download"
  fi
  local download_bases=()
  if [ -n "$version" ]; then
    download_bases=("$gh_base")
  else
    download_bases=("$cdn_base" "$gh_base")
  fi
  local raw_url="${cdn_base}/install.sh"

  # -----------------------------------------------------------------------
  # Parse our own flags out of "$@"; everything else is forwarded verbatim
  # to `belay setup` (e.g. --home, or the wizard's own --yes).
  # -----------------------------------------------------------------------
  local skip_setup=0
  local setup_args=()
  for arg in "$@"; do
    case "$arg" in
      --skip-setup | --no-setup | -y)
        skip_setup=1
        ;;
      *)
        setup_args+=("$arg")
        ;;
    esac
  done

  # -----------------------------------------------------------------------
  # Detect OS + arch -> release asset name. Hard-fails (via
  # belay_detect_target's own return 1) on anything unrecognized.
  # -----------------------------------------------------------------------
  local os arch target
  os="$(uname -s)"
  arch="$(uname -m)"
  if ! target="$(belay_detect_target "$os" "$arch")"; then
    exit 1
  fi
  if [ "$os" = "Linux" ]; then
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
      echo "belay-install: host libc: musl" >&2
    else
      echo "belay-install: host libc: glibc (or undetected) -- installing the statically-linked musl build, which runs on any Linux libc" >&2
    fi
  fi

  local asset="belay-${target}"
  echo "belay-install: target ${target} -> ${asset}" >&2

  # -----------------------------------------------------------------------
  # Download to a temp dir, forced TLS, cleaned up on exit no matter how we
  # leave this function (including on a hard failure below). Deliberately
  # NOT `local`: the EXIT trap fires at top-level script exit, after `main`
  # has already returned and its locals have gone out of scope -- under
  # `set -u` a `local tmp` here would make the trap itself blow up with
  # "tmp: unbound variable" instead of cleaning up.
  # -----------------------------------------------------------------------
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Try each download host in order. The binary and its SHA256SUMS must come
  # from the SAME host, so the checksum always matches the bytes we fetched; a
  # host that lacks this platform's asset (404) is skipped, never mixed with
  # another host's checksum file.
  local dl_base="" b
  for b in "${download_bases[@]}"; do
    echo "belay-install: downloading ${asset} from ${b} ..." >&2
    if curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/belay" "${b}/${asset}" \
       && curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/SHA256SUMS" "${b}/SHA256SUMS"; then
      dl_base="$b"
      break
    fi
    echo "belay-install: ${b} did not serve ${asset}; trying next source ..." >&2
  done
  if [ -z "$dl_base" ]; then
    echo "belay-install: could not download ${asset} from any source (${download_bases[*]})." >&2
    exit 1
  fi

  # -----------------------------------------------------------------------
  # Verify the checksum BEFORE chmod/install/exec. Refuses (exit 1) on a
  # mismatch. If neither tool exists, warn loudly but continue best-effort
  # (matches cargo-dist's own installer behavior).
  # -----------------------------------------------------------------------
  if command -v sha256sum >/dev/null 2>&1; then
    if ! (cd "$tmp" && grep " ${asset}\$" SHA256SUMS | sed "s/${asset}\$/belay/" | sha256sum -c -); then
      echo "belay-install: SHA-256 verification FAILED -- refusing to install." >&2
      exit 1
    fi
    echo "belay-install: checksum verified (sha256sum)." >&2
  elif command -v shasum >/dev/null 2>&1; then
    if ! (cd "$tmp" && grep " ${asset}\$" SHA256SUMS | sed "s/${asset}\$/belay/" | shasum -a 256 -c -); then
      echo "belay-install: SHA-256 verification FAILED -- refusing to install." >&2
      exit 1
    fi
    echo "belay-install: checksum verified (shasum -a 256)." >&2
  else
    echo "belay-install: WARNING: neither sha256sum nor shasum found -- cannot verify the download's integrity. Proceeding WITHOUT checksum verification (best-effort)." >&2
  fi

  chmod +x "$tmp/belay"

  # -----------------------------------------------------------------------
  # Install: write-probe the target dir (not a UID check) to decide whether
  # sudo is needed.
  # -----------------------------------------------------------------------
  if (: >"$install_dir/.belay-install-probe") 2>/dev/null; then
    rm -f "$install_dir/.belay-install-probe"
    mv "$tmp/belay" "$install_dir/belay"
  else
    echo "belay-install: ${install_dir} is not writable; using sudo ..." >&2
    sudo mkdir -p "$install_dir"
    sudo mv "$tmp/belay" "$install_dir/belay"
  fi
  echo "belay-install: installed ${install_dir}/belay"

  # -----------------------------------------------------------------------
  # Hand off to the setup wizard, reconnecting /dev/tty when stdin is the
  # curl pipe so the interactive prompts still work under `curl | bash`.
  #
  # `belay_setup` guards the `"${setup_args[@]}"` expansion behind a
  # length check (`${#setup_args[@]}`) rather than expanding it directly: on
  # macOS's default /bin/bash (still 3.2, pre-GPLv3), `"${empty_array[@]}"`
  # under `set -u` throws "unbound variable" instead of expanding to nothing
  # (fixed upstream in bash 4.4) -- this is the common no-extra-flags case
  # (plain `curl | bash`), so it has to work on stock macOS.
  # -----------------------------------------------------------------------
  belay_setup() {
    if [ "${#setup_args[@]}" -gt 0 ]; then
      "$install_dir/belay" setup "${setup_args[@]}"
    else
      "$install_dir/belay" setup
    fi
  }

  if [ "$skip_setup" -eq 1 ]; then
    echo "belay-install: setup skipped; run '${install_dir}/belay setup' yourself when ready."
  elif [ -t 0 ]; then
    belay_setup
  elif (: </dev/tty) 2>/dev/null; then
    if ! belay_setup </dev/tty; then
      "$install_dir/belay" setup --yes
    fi
  else
    echo "belay-install: no controlling terminal available for the interactive wizard; running 'belay setup --yes' (Quick defaults)." >&2
    if ! "$install_dir/belay" setup --yes; then
      echo "belay-install: run '${install_dir}/belay setup' manually to finish configuring Belay." >&2
    fi
  fi

  echo
  echo "Review this script before piping it to bash next time:"
  echo "  curl -fsSL ${raw_url} -o install.sh && less install.sh && bash install.sh"
  echo "Uninstall anytime with: belay uninstall"
}

main "$@"
