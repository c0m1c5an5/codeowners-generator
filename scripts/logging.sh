#!/bin/sh
# shellcheck disable=SC3043
# SC3043 (warning): In POSIX sh, 'local' is undefined
# Reason: Works with all current shells

_bashlog_cap_color="$(tput colors >/dev/null 2>&1 && echo '1' || echo '0')"

log() {
  local level debug_level message no_color color clear date std_message

  level="$(printf '%s' "${1}" | tr '[:upper:]' '[:lower:]')"
  shift 1
  message="${*}"

  if [ -z "${DEBUG+x}" ] || [ "${DEBUG:-}" = "0" ] || [ "${DEBUG:-}" = "false" ]; then
    debug_level=0
  else
    debug_level=1
  fi

  if [ "${_bashlog_cap_color}" -eq 1 ] && [ -z "${NO_COLOR+x}" ] ||
    [ "${NO_COLOR:-}" = "0" ] || [ "${NO_COLOR:-}" = "false" ]; then
    no_color=0
  else
    no_color=1
  fi

  case "${level}" in                                                # RFC 5424
  err) [ "${no_color}" -eq 0 ] && color="$(printf '\033[31m')" ;;   # Error: error conditions
  warn) [ "${no_color}" -eq 0 ] && color="$(printf '\033[33m')" ;;  # Warning: warning conditions
  info) [ "${no_color}" -eq 0 ] && color="$(printf '\033[32m')" ;;  # Informational: informational messages
  debug) [ "${no_color}" -eq 0 ] && color="$(printf '\033[34m')" ;; # Debug: debug-level messages
  *)
    log 'err' "Undefined log level '${level}' trying to log: ${*}"
    return
    ;;
  esac

  [ "${no_color}" -eq 0 ] && clear="$(printf '\033[0m')"

  if ! [ "${level}" = 'debug' ] || [ "${debug_level}" -ne 0 ]; then
    date="$(date "${BASHLOG_DATE_FORMAT:-+%F %T}")"
    std_message="${color:-}${date} [${level}] ${message}${clear:-}"
    echo "${std_message}" >&2
  fi
}
