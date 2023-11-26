function Get-LHSAntiVirusProduct 
{
<#
.SYNOPSIS
    AUTHOR: Pasquale Lantella 
    LASTEDIT: 23.06.2016
    KEYWORDS: Antivirus
    Version :1.1
    History :1.1 support for Win 10, changed the use of WMI productState
.PWN
    # (New-Object System.Net.WebClient).DownloadString('http://192.168.45.160/Get-AVProduct.min.ps1') | IEX
#Requires -Version 2.0
#>
[CmdletBinding()]
param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('CN')]
    [String[]]$ComputerName=$env:computername
)
BEGIN {
    Set-StrictMode -Version Latest
    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name
}
PROCESS {
    ForEach ($Computer in $computerName) 
    {
        IF (Test-Connection -ComputerName $Computer -count 2 -quiet) 
        { 
            Try
            {
                [system.Version]$OSVersion = (Get-WmiObject win32_operatingsystem -computername $Computer).version
                IF ($OSVersion -ge [system.version]'6.0.0.0') {
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computer -ErrorAction Stop
                } 
                Else {
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop
                }
                $productState = $AntiVirusProduct.productState
    			$hex = [convert]::ToString($productState[0], 16).PadLeft(6,'0')
                # Substring(int startIndex, int length)  
                $WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2)
                $WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2)
                $RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE)
                {
                    "00" {"OFF"} 
                    "01" {"EXPIRED"}
                    "10" {"ON"}
                    "11" {"SNOOZED"}
                    default {"UNKNOWN"}
                }
                $DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS)
                {
                    "00" {"UP_TO_DATE"}
                    "10" {"OUT_OF_DATE"}
                    default {"UNKNOWN"}
                }  
                $AV = $Null
                $AV = New-Object -TypeName PSObject -ErrorAction Stop -Property @{
 
                    ComputerName = $AntiVirusProduct.__Server;
                    Name = $AntiVirusProduct.displayName;
                    ProductExecutable = $AntiVirusProduct.pathToSignedProductExe;
                    ReportingExecutable = $AntiVirusProduct.pathToSignedReportingExe;
                    DefinitionStatus = $DefinitionStatus;
                    RealTimeProtectionStatus = $RealTimeProtectionStatus;
                    ProductState = $productState;
                } | Select-Object ComputerName,Name,ProductExecutable,ReportingExecutable,DefinitionStatus,RealTimeProtectionStatus,ProductState 
                Write-Output $AV 
            }
            Catch 
            {
                Write-Error "\\$Computer : WMI Error"
                Write-Error $_
            }                              
        } 
        Else 
        {
            Write-Warning "\\$computer DO NOT reply to ping" 
        }
    }
}
}
Get-LHSAntiVirusProduct
