# DeFOG

Lightweight Windows triage collector in Go: memory capture and live response artifacts in a single binary.

DeFOG is built for incident responders who need to grab volatile evidence from a Windows host quickly and consistently. It runs as one executable with no PowerShell, .NET or installer required, so it works on hosts where scripting is locked down or can't be trusted.

> **Why "DeFOG"?** FOG comes from "eyes on glass," a phrase from the SOC where this tool started. DeFOG clears the fog on a compromised host.

## Features

- **Memory capture** using the bundled, signed [WinPmem](https://github.com/Velocidex/WinPmem) release, with pre-checks for admin rights, free space and FAT32 output drives
- **Capture documentation:** image size, SHA256, start/end times, duration, and the exact tool path, version and hash written to `memory_info.txt`
- **Live response collection** of 30+ artifacts across network, processes, users, persistence, security posture and system info
- **Process hashing and signature checks** for every running executable
- **Parallel collection:** independent live response steps run concurrently, limited to a few at a time to keep load on the host low
- **Self-contained output:** everything lands in a timestamped case folder on the collection drive

## Requirements

- Windows 10 / Windows Server 2016 or newer, 64-bit (x64)
- Administrator rights (required for memory capture and several live response artifacts)
- A collection drive formatted **NTFS or exFAT** with free space greater than the host's RAM (FAT32 can't hold files over 4 GB)

Memory capture is not supported on Windows on ARM, because the WinPmem kernel driver is x64 only.

## Quick start

1. Download `defog.exe` from the [Releases](../../releases) page and verify its SHA256 against the one listed there.
2. Optionally, download [Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) and [Sigcheck](https://learn.microsoft.com/sysinternals/downloads/sigcheck) from Microsoft and place `autorunsc64.exe` and `sigcheck64.exe` in `Tools\Sysinternals`.
3. Copy everything to your collection drive:

   ```
   E:\
     defog.exe
     Tools\
       Sysinternals\
         autorunsc64.exe
         sigcheck64.exe
   ```

4. On the target host, run `defog.exe` from an elevated prompt and choose an option:

   | Option | Action |
   |---|---|
   | `1` | Full collection (memory, then live response) |
   | `2` | Memory capture only |
   | `3` | Live response only |
   | `Q` | Quit |

The Sysinternals tools are optional. Without them, DeFOG skips Autoruns and records hashes without signature status.

## What gets collected

Output is written next to `defog.exe`:

```
Cases\
  <HOST>_<yyyyMMddTHHmmssZ>\
    RawMemory\
      <HOST>_memory.raw
      memory_info.txt
    LiveResponse\
      ...
    Tools\
      go-winpmem_amd64_1.0-rc2_signed.exe
```

The extracted WinPmem copy is kept in the case folder as a record of the exact binary that ran.

### Live response artifacts

| Category | Files |
|---|---|
| Time | `time.txt` (local and UTC time, time zone, uptime, boot time) |
| Network | `net_tcp.csv`, `net_udp.csv`, `netstat.txt`, `dns_cache.csv`, `arp.txt`, `routes.txt`, `ipconfig.txt` |
| Processes | `processes.csv` (with command lines and owners), `process_hashes.csv` (SHA256, signature status, signer) |
| Users & sessions | `logged_on_users.txt`, `local_users.csv`, `local_admins.txt`, `net_sessions.txt`, `net_use.txt`, `shares.csv` |
| Persistence | `services.csv`, `scheduled_tasks.csv`, `startup_commands.csv`, `wmi_consumers.csv`, `wmi_filters.csv`, `wmi_bindings.csv`, `autoruns.csv` |
| Security posture | `bitlocker.txt`, `defender_status.txt`, `defender_exclusions.txt`, `firewall_profiles.csv` |
| System info | `OS.csv`, `computer_system.csv`, `hotfixes.csv`, `disk_partitions.csv`, `volumes.csv`, `env_vars.txt` |

## Building from source

Requires the current Go release.

1. Clone the repository.
2. Download `go-winpmem_amd64_1.0-rc2_signed.exe` from the official [WinPmem releases](https://github.com/Velocidex/WinPmem/releases) and place it at:

   ```
   tools/winpmem/go-winpmem_amd64_1.0-rc2_signed.exe
   ```

   WinPmem is embedded into the binary at build time, so the build fails if this file is missing.

3. Build:

   ```powershell
   go mod download
   $env:CGO_ENABLED = "0"
   $env:GOOS = "windows"
   $env:GOARCH = "amd64"
   go build -trimpath -o defog.exe .
   ```

### Icon and version info (optional)

The icon and version metadata are generated with [go-winres](https://github.com/tc-hib/go-winres):

```powershell
go install github.com/tc-hib/go-winres@latest
go-winres make
go build -trimpath -o defog.exe .
```

## Operational notes

- **Memory first.** Option 1 captures memory before live response, so DeFOG's own activity doesn't end up in the memory image.
- **Write to your drive, not the host's.** Run DeFOG from the collection drive so case output and the extracted WinPmem never touch the target's disk.
- **Expect EDR attention.** DeFOG loads a kernel driver to read physical memory, which security tools watch closely. Allowlist it and notify your SOC before running it during an incident.
- **Hashes cover files on disk.** `process_hashes.csv` hashes each executable's file, not its in-memory image. Use the memory capture to look for in-memory tampering.

## Third-party software

- **WinPmem** (Velocidex) is bundled unmodified under the Apache License 2.0. See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
- **Sysinternals Autoruns and Sigcheck** are not distributed with DeFOG. Download them directly from Microsoft.

## License

DeFOG is released under the [MIT License](LICENSE).

## Disclaimer

DeFOG is provided as-is, without warranty. Use it only on systems you own or are explicitly authorized to examine.
