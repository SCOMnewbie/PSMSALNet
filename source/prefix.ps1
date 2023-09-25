# This is required to expose in a private way the cmdlet Get-WAMToken which is required when we use the -WAMFlow
import-module $(Join-Path $PSScriptRoot 'lib' 'WAMHelper.dll') -ErrorAction Stop
