# Powershell Script to Create Self-Signed Cert and Sign Agent
# Note: Browsers will STILL warn unless this cert is installed in "Trusted Root Certification Authorities" on the victim machine.
# To remove warnings for everyone, you must BUY a certificate from Sectigo/DigiCert ($300+/yr).

$CertName = "WatchSecMonitorix"
$ExePath = "$PSScriptRoot\dist\monitorix\monitorixagent.exe"

Write-Host "1. Checking for existing certificate..." -ForegroundColor Cyan
$ExistingCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$CertName" } | Select-Object -First 1

if ($ExistingCert) {
    Write-Host "Found existing certificate: $($ExistingCert.Thumbprint)" -ForegroundColor Green
    $cert = $ExistingCert
} else {
    Write-Host "Generating New Self-Signed Code Signing Certificate..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -CertStoreLocation Cert:\CurrentUser\My
}

if (!$cert) {
    Write-Host "Error generating/finding certificate" -ForegroundColor Red
    exit
}

# Export Public Certificate (for Root Trust)
$PublicCertPath = "$PSScriptRoot\dist\root_ca.crt"
Write-Host "Exporting Public Certificate to $PublicCertPath..."
$CertBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($PublicCertPath, $CertBytes)

# Export to PFX (Optional, if you want to sign on other machines)
# $Password = ConvertTo-SecureString -String "Password123" -Force -AsPlainText
# Export-PfxCertificate -Cert $cert -FilePath "WatchSec.pfx" -Password $Password

Write-Host "2. Signing Executable..." -ForegroundColor Cyan
if (Test-Path $ExePath) {
    Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert
    Write-Host "Success! Signed $ExePath" -ForegroundColor Green
    Write-Host "You can verify by Right Click -> Properties -> Digital Signatures" -ForegroundColor Yellow
} else {
    Write-Host "Error: $ExePath not found. Build the agent first." -ForegroundColor Red
}
