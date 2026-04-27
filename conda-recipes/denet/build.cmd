@echo off
cargo build --release --bin denet
if errorlevel 1 exit /b 1
copy /Y target\release\denet.exe %PREFIX%\Library\bin\denet.exe
