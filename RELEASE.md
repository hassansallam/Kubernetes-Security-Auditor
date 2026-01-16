# Release Process

This document describes how to create a new release of the K8s Security Auditor.

## Automated Release via GitHub Actions

The project uses GitHub Actions to automatically build and publish releases for multiple platforms.

### Creating a Release

#### Method 1: Tag-based Release (Recommended)

1. **Update version references** (if needed):
   ```bash
   # Update any version strings in documentation
   git add .
   git commit -m "Prepare for version vX.Y.Z"
   ```

2. **Create and push a version tag**:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **GitHub Actions will automatically**:
   - Build binaries for all platforms:
     - Linux (amd64, arm64)
     - macOS (amd64, arm64)
     - Windows (amd64)
   - Generate SHA256 checksums
   - Create a GitHub Release
   - Upload all binaries and checksums

#### Method 2: Manual Workflow Trigger

1. Go to **Actions** tab in GitHub repository
2. Select **Release Binaries** workflow
3. Click **Run workflow**
4. Enter the version tag (e.g., `v1.0.0`)
5. Click **Run workflow**

### Supported Platforms

The release workflow builds for:

| Platform | Architecture | Binary Name |
|----------|-------------|-------------|
| Linux | amd64 | `k8s-security-auditor-linux-amd64` |
| Linux | arm64 | `k8s-security-auditor-linux-arm64` |
| macOS | amd64 (Intel) | `k8s-security-auditor-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `k8s-security-auditor-darwin-arm64` |
| Windows | amd64 | `k8s-security-auditor-windows-amd64.exe` |

### Release Contents

Each release includes:

1. **Binaries**: Pre-compiled executables for all platforms
2. **Checksums**: Individual `.sha256` files for each binary
3. **Combined checksums**: `checksums.txt` with all binary checksums
4. **Release Notes**: Automatically generated with:
   - Installation instructions for each platform
   - Quick start guide
   - Links to documentation
   - Changelog reference

## Manual Build (Local Development)

If you need to build binaries locally:

### Using build.sh (Linux/macOS)

```bash
chmod +x build.sh
VERSION=v1.0.0 ./build.sh
```

### Using build.bat (Windows)

```cmd
set VERSION=v1.0.0
build.bat
```

### Manual Build Commands

```bash
# Set version
export VERSION=v1.0.0

# Linux amd64
GOOS=linux GOARCH=amd64 go build -o k8s-security-auditor-linux-amd64 \
  -ldflags "-X main.version=${VERSION}" .

# Linux arm64
GOOS=linux GOARCH=arm64 go build -o k8s-security-auditor-linux-arm64 \
  -ldflags "-X main.version=${VERSION}" .

# macOS amd64
GOOS=darwin GOARCH=amd64 go build -o k8s-security-auditor-darwin-amd64 \
  -ldflags "-X main.version=${VERSION}" .

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o k8s-security-auditor-darwin-arm64 \
  -ldflags "-X main.version=${VERSION}" .

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o k8s-security-auditor-windows-amd64.exe \
  -ldflags "-X main.version=${VERSION}" .
```

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: Add functionality (backward compatible)
- **PATCH** version: Bug fixes (backward compatible)

Examples:
- `v1.0.0` - Initial release
- `v1.1.0` - New features added
- `v1.1.1` - Bug fixes
- `v2.0.0` - Breaking changes

## Release Checklist

Before creating a release:

- [ ] All tests pass
- [ ] Documentation is up to date
- [ ] UPDATES_SUMMARY.md reflects latest changes
- [ ] No security vulnerabilities (`go list -json -m all | nancy sleuth`)
- [ ] Dependencies are up to date (`go mod tidy`)
- [ ] Version number follows semantic versioning
- [ ] Tag format is `vX.Y.Z` (e.g., `v1.0.0`)

## Verifying a Release

After release is published:

1. **Download binary for your platform**:
   ```bash
   curl -L https://github.com/hassansallam/k8s-security-auditor/releases/download/v1.0.0/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
   ```

2. **Verify checksum**:
   ```bash
   curl -L https://github.com/hassansallam/k8s-security-auditor/releases/download/v1.0.0/k8s-security-auditor-linux-amd64.sha256 -o checksum.txt
   sha256sum -c checksum.txt
   ```

3. **Test the binary**:
   ```bash
   chmod +x k8s-security-auditor
   ./k8s-security-auditor --show-version
   ```

## Hotfix Releases

For urgent security fixes:

1. Create a hotfix branch from the release tag:
   ```bash
   git checkout -b hotfix/v1.0.1 v1.0.0
   ```

2. Apply the fix and commit:
   ```bash
   git commit -am "Fix critical security issue"
   ```

3. Create new tag:
   ```bash
   git tag -a v1.0.1 -m "Hotfix v1.0.1"
   git push origin v1.0.1
   ```

## Troubleshooting

### Release Workflow Fails

1. **Check Go version**: Workflow uses Go 1.21
2. **Check dependencies**: Ensure `go.mod` is valid
3. **Check permissions**: Ensure `GITHUB_TOKEN` has write permissions
4. **View logs**: Go to Actions tab and check workflow logs

### Binary Won't Run

1. **Make executable** (Linux/macOS):
   ```bash
   chmod +x k8s-security-auditor
   ```

2. **Check architecture**:
   ```bash
   uname -m  # Should match binary architecture
   ```

3. **Check dependencies**:
   ```bash
   ldd k8s-security-auditor  # Linux
   otool -L k8s-security-auditor  # macOS
   ```

## Release Automation

The GitHub Actions workflow (`.github/workflows/release.yml`) handles:

1. **Build Stage**: Compiles binaries for all platforms in parallel
2. **Release Stage**: Creates GitHub release with all artifacts
3. **Checksums**: Generates SHA256 for verification
4. **Release Notes**: Auto-generates comprehensive release notes

## Support

For questions about releases:
- Open an issue: https://github.com/hassansallam/k8s-security-auditor/issues
- Review existing releases: https://github.com/hassansallam/k8s-security-auditor/releases
