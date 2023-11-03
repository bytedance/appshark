#!/usr/bin/env sh

if [ "$(uname)" = "Darwin" ]; then
  if ! command -v gtimeout > /dev/null 2>&1
  then
    echo "Please install gtimeout and try again: \"brew install coreutils\""
    exit 0
  fi
  alias timeout=gtimeout
fi

jadx=$1
apk=$2
output=$3
ds=$4

done_file=$output/.done

if [ -f "$done_file" ]
then
  exit 0
fi

rm -rf "$output"

#timeout -s SIGKILL 1800 $jadx --quiet \
#      --no-imports \
#      --no-res \
#      --show-bad-code \
#      --no-debug-info \
#      --output-dir-src "$output" \
#      --threads-count "$ds" \
#      "$apk"

timeout -s SIGKILL 1800 $jadx --quiet \
      --no-imports \
      --show-bad-code \
      --no-debug-info \
      --output-dir "$output" \
      --threads-count "$ds" \
      --export-gradle \
      "$apk"

touch "$done_file"
