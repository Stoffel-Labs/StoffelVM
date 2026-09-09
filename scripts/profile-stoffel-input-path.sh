#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 HOST_PID [TARGET_BINARY] [RAW_OUTPUT]" >&2
  exit 2
fi

target_pid=$1
case "$target_pid" in
  ''|*[!0-9]*|0)
    echo "HOST_PID must be a positive integer" >&2
    exit 2
    ;;
esac

target_binary=${2:-/proc/$target_pid/root/app/stoffel-run}
raw_output=${3:-stoffel-input-path-$target_pid.txt}
case "$target_binary" in
  *'#'*)
    echo "TARGET_BINARY cannot contain '#'" >&2
    exit 2
    ;;
esac
if [ ! -r "$target_binary" ]; then
  echo "target binary is not readable: $target_binary" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rendered_script=$(mktemp "${TMPDIR:-/tmp}/stoffel-input-path.XXXXXX")
trap 'rm -f -- "$rendered_script"' EXIT INT TERM

sed "s#__TARGET_BINARY__#$target_binary#" \
  "$script_dir/stoffel-input-path.bt" >"$rendered_script"

bpftrace -o "$raw_output" "$rendered_script" "$target_pid"
awk -f "$script_dir/summarize-stoffel-input-path.awk" "$raw_output"
