<##############################################################################
Ashley McGlone
Microsoft Premier Field Engineer
April 2014
http://aka.ms/GoateePFE

Module for Group Policy migration.

Requirements / Setup
-Windows 7/2008 R2 (or above) RSAT with AD PowerShell cmdlets installed.
-GPMC with GroupPolicy module installed.
-Import-Module GroupPolicy
-Import-Module ActiveDirectory

These are the default permissions required unless specific permission
delegations have been created:
Domain Admins to create policies and link them.
Enterprise Admins if linking policies to sites.


LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
 
This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at http://www.microsoft.com/info/cpyright.htm.
##########################################################################sdg#>



<##############################################################################
Setup

Your working folder path should include a copy of this script, and a copy of
the GPOMigration.psm1 module file.

This example assumes that a backup will run under a source credential and server,
and the import will run under a destination credential and server.  Between these
two operations you will need to copy your working folder from one environment to
the other.

Modify the following to your needs:
 working folder path
 source domain and server
 destination domain and server
 the GPO DisplayName Where criteria to target your policies for migration
##############################################################################>

Set-Location C:\terraform\threathunt\labsetup\DC\GPOmigration\

Import-Module GroupPolicy
Import-Module ActiveDirectory
Import-Module ".\GPOMigration" -Force

# This path must be absolute, not relative
$Path        = $PWD  # Current folder specified in Set-Location above
$SrceDomain  = 'acme.local'
$SrceServer  = 'DC01.acme.local'
$DisplayName = Get-GPO -All -Domain $SrceDomain -Server $SrceServer |
    Where-Object {$_.DisplayName -like '*threathunt*'} | 
    Select-Object -ExpandProperty DisplayName

Start-GPOExport `
    -SrceDomain $SrceDomain `
    -SrceServer $SrceServer `
    -DisplayName $DisplayName `
    -Path $Path
    
###############################################################################
# END
###############################################################################
