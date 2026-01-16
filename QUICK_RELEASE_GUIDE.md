# Quick Release Guide

## Fix the Missing go.sum Issue

Before you can create releases, you need to generate the `go.sum` file. Here's how:

### Step 1: Generate go.sum via GitHub Actions

1. Go to your repository: https://github.com/hassansallam/k8s-security-auditor
2. Click on the **Actions** tab
3. Find and click on **Generate go.sum** workflow in the left sidebar
4. Click the **Run workflow** button (on the right side)
5. Click the green **Run workflow** button in the popup
6. Wait for the workflow to complete (takes ~30 seconds)
7. The workflow will automatically commit and push the `go.sum` file

### Step 2: Create Your First Release

After `go.sum` is generated and committed:

#### Option A: Create a Release Tag (Recommended)

```bash
# Pull the latest changes (including go.sum)
git pull origin main

# Create a release tag
git tag -a v1.0.0 -m "Release v1.0.0 - Initial release"

# Push the tag
git push origin v1.0.0
```

#### Option B: Manual Workflow Trigger

1. Go to **Actions** tab
2. Click on **Release Binaries** workflow
3. Click **Run workflow**
4. Enter version: `v1.0.0`
5. Click **Run workflow**

### Step 3: Check the Release

1. Go to the **Actions** tab and watch the build progress
2. Once complete, go to: https://github.com/hassansallam/k8s-security-auditor/releases
3. You should see your new release with all binaries!

## What You'll Get

Each release includes:

- ✅ `k8s-security-auditor-linux-amd64` - Linux 64-bit binary
- ✅ `k8s-security-auditor-linux-arm64` - Linux ARM64 binary
- ✅ `k8s-security-auditor-darwin-amd64` - macOS Intel binary
- ✅ `k8s-security-auditor-darwin-arm64` - macOS Apple Silicon binary
- ✅ `k8s-security-auditor-windows-amd64.exe` - Windows 64-bit executable
- ✅ Individual `.sha256` checksum files
- ✅ Combined `checksums.txt` file
- ✅ Comprehensive installation instructions in the release notes

## Troubleshooting

### If Generate go.sum workflow fails:

The workflow might fail if you don't have Go installed or if there are module issues. In that case:

1. Install Go 1.21+ locally
2. Run: `go mod tidy`
3. Commit: `git add go.sum && git commit -m "Add go.sum"`
4. Push: `git push origin main`

### If Release workflow fails:

1. Check the Actions tab for error logs
2. Ensure `go.sum` exists in the repository
3. Verify that all dependencies in `go.mod` are valid
4. Check that Go version is 1.21 in the workflow

## Next Steps

After your first successful release:

1. Update README.md with the actual release link
2. Test downloading and running the binaries
3. Share your release! 🎉

For more details, see [RELEASE.md](RELEASE.md).
