# Monitorix Software Bill of Materials (SBOM) & Artifact Trust

This guide explains how to verify the integrity and transparency of the Monitorix platform's software supply chain.

## 1. What is an SBOM?
A Software Bill of Materials (SBOM) is a formal record containing the details and supply chain relationships of various components used in building software. Monitorix generates an SBOM in **CycloneDX JSON** format on every release.

## 2. Verifying the SBOM
You can find the latest SBOM in the GitHub Actions artifacts or the release assets. To inspect it:

```bash
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Scan the Monitorix image and compare with SBOM
syft monitorix-backend:latest -o cyclonedx-json > current-scan.json
diff monitorix-sbom.json current-scan.json
```

## 3. Verifying Artifact Signatures
Monitorix Docker images are signed using `cosign`. To verify an image before deployment:

```bash
# Install cosign
LATEST_VERSION=$(curl -L -s -H 'Accept: application/json' https://github.com/sigstore/cosign/releases/latest | sed -e 's/.*"tag_name":"\([^"]*\)".*/\1/')
pip install cosign

# Verify the image signature
cosign verify --key cosign.pub monitorix/backend:latest
```

## 4. Supply Chain Policy
- **Scan-on-Push**: Every code change is scanned for vulnerabilities (Bandit/Safety).
- **Non-Root Execution**: Containers run as an unprivileged system user (`monitorix`).
- **Dependency Pinning**: All Python and system dependencies are pinned to specific versions to prevent supply chain poisoning.
