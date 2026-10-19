@echo off
rem ---------------------------------------------------------------
rem  Wrapper for campus-sso-login.ps1.
rem
rem  Windows ships with ExecutionPolicy=Restricted, which refuses to
rem  run any .ps1. -ExecutionPolicy Bypass applies to this one process
rem  only: nothing is changed on the machine and no admin rights are
rem  needed. %* forwards any arguments (e.g. -Sms 138..., -Logout).
rem ---------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0campus-sso-login.ps1" %*
