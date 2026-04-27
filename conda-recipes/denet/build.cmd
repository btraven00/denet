@echo off
cargo install --path . --bin denet --root "%PREFIX%\Library" --no-track
if errorlevel 1 exit /b 1
