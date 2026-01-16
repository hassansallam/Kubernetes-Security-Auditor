@echo off
REM K8s Security Auditor - Cross-platform Build Script (Windows)
REM Builds binaries for Linux, macOS, and Windows

setlocal

if "%VERSION%"=="" set VERSION=v1.0.0
set BINARY_NAME=k8s-security-auditor
set OUTPUT_DIR=dist

echo Building K8s Security Auditor %VERSION%
echo =========================================

REM Clean previous builds
if exist %OUTPUT_DIR% rmdir /s /q %OUTPUT_DIR%
mkdir %OUTPUT_DIR%

REM Ensure dependencies are tidy
echo Tidying dependencies...
go mod tidy

REM Get dependencies
echo Downloading dependencies...
go mod download

REM Build for Linux amd64
echo Building for Linux amd64...
set GOOS=linux
set GOARCH=amd64
go build -o %OUTPUT_DIR%\%BINARY_NAME%-linux-amd64 -ldflags "-X main.version=%VERSION%" .

REM Build for Linux arm64
echo Building for Linux arm64...
set GOOS=linux
set GOARCH=arm64
go build -o %OUTPUT_DIR%\%BINARY_NAME%-linux-arm64 -ldflags "-X main.version=%VERSION%" .

REM Build for macOS amd64
echo Building for macOS amd64...
set GOOS=darwin
set GOARCH=amd64
go build -o %OUTPUT_DIR%\%BINARY_NAME%-darwin-amd64 -ldflags "-X main.version=%VERSION%" .

REM Build for macOS arm64 (Apple Silicon)
echo Building for macOS arm64...
set GOOS=darwin
set GOARCH=arm64
go build -o %OUTPUT_DIR%\%BINARY_NAME%-darwin-arm64 -ldflags "-X main.version=%VERSION%" .

REM Build for Windows amd64
echo Building for Windows amd64...
set GOOS=windows
set GOARCH=amd64
go build -o %OUTPUT_DIR%\%BINARY_NAME%-windows-amd64.exe -ldflags "-X main.version=%VERSION%" .

echo.
echo Build complete! Binaries:
echo ========================
dir %OUTPUT_DIR%

echo.
echo Build artifacts saved to: %OUTPUT_DIR%\

endlocal
