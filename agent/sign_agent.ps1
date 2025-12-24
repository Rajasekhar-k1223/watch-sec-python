# Powershell Script to Create Self-Signed Cert and Sign Agent
# Note: Browsers will STILL warn unless this cert is installed in "Trusted Root Certification Authorities" on the victim machine.
# To remove warnings for everyone, you must BUY a certificate from Sectigo/DigiCert ($300+/yr).

$CertName = "WatchSecInternalDev"
$ExePath = "dist\watch-sec-agent.exe"

Write-Host "1. Generating Self-Signed Code Signing Certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -CertStoreLocation Cert:\CurrentUser\My

if (!$cert) {
    Write-Host "Error generating certificate" -ForegroundColor Red
    exit
}

Write-Host "Certificate Created: $($cert.Thumbprint)" -ForegroundColor Green

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
