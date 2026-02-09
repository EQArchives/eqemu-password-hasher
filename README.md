# eqemu-password-hasher
Generate and Verify Password Hashes for TAKP and PEQ Accounts

[![Build](https://github.com/EQArchives/eqemu-password-hasher/actions/workflows/build.yml/badge.svg)](https://github.com/EQArchives/eqemu-password-hasher/actions/workflows/build.yml)

Generate and Verify Password Hashes for TAKP and PEQ Accounts

<img width="699" height="596" alt="Screenshot" src="https://github.com/user-attachments/assets/28dd0a23-9bd1-495e-b36e-f9947a102f03" />

## Download

**Latest stable release:**
- [Windows](https://github.com/EQArchives/eqemu-password-hasher/releases/latest/download/eqemu-password-hasher.exe)
- [macOS](https://github.com/EQArchives/eqemu-password-hasher/releases/latest/download/eqemu-password-hasher.app)
- [Linux](https://github.com/EQArchives/eqemu-password-hasher/releases/latest/download/eqemu-password-hasher.tar.xz)

[View all releases](https://github.com/EQArchives/eqemu-password-hasher/releases)

## Prerequisites

- Go 1.21 or higher
- Fyne dependencies (see [Fyne Getting Started](https://developer.fyne.io/started/))

### Platform-specific dependencies

**macOS:**
```bash
# Xcode command line tools
xcode-select --install
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install gcc libgl1-mesa-dev xorg-dev

# Fedora/RHEL
sudo dnf install gcc libXcursor-devel libXrandr-devel mesa-libGL-devel libXi-devel libXinerama-devel libXxf86vm-devel
```

**Windows:**
- Install [Go for Windows](https://golang.org/dl/)
- GCC via [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or [MSYS2](https://www.msys2.org/)

## Quick Start

### 1. Clone the repository
```bash
git clone git@github.com:EQArchives/eqemu-password-hasher.git
cd eqemu-password-hasher/
```

### 2. Install dependencies
```bash
go mod download
```

### 3. Run the app
```bash
go run .
```

### 4. Build the app
```bash
# Build for current platform
go build -o myapp

# Or use fyne package for a distributable app
go install fyne.io/fyne/v2/cmd/fyne@latest
fyne package -icon Icon.png
```

### Cross-compile for other platforms (optional)
```bash
# Install fyne-cross
go install github.com/fyne-io/fyne-cross@latest

# Build for specific platforms
fyne-cross windows -arch=amd64
fyne-cross darwin -arch=amd64,arm64
fyne-cross linux -arch=amd64
```

Binaries will be in `fyne-cross/dist/`.

## Testing
```bash
go test ./...
```

## Development
```bash
# Run tests with coverage
go test -cover ./...

# Run with hot reload (install air first)
go install github.com/cosmtrek/air@latest
air
```

## License
[MIT]
