@echo off
set jadx=%1
set apk=%2
set output=%3
set ds=%4

set done_file=%output%\.done

if exist "%done_file%" goto :eof

del /s /q "%output%"

%jadx% --quiet ^
      --no-imports ^
      --show-bad-code ^
      --no-debug-info ^
      --output-dir "%output%" ^
      --threads-count "%ds%" ^
      --export-gradle ^
      "%apk%"

echo > "%done_file%"
