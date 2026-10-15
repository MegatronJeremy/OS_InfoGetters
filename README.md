# OS Info Getters

Windows has several ways to ask which version of the OS is running, and they don't all agree.
`GetVersionEx`, for example, reports the version the application is manifested for rather than the
real one. This program calls each approach side by side so the answers can be compared:

| Function | Source |
| --- | --- |
| `GetOSVersion` | `GetVersionEx` (deprecated, affected by compatibility manifests) |
| `GetRealOSVersion` | `RtlGetVersion` from `ntdll.dll` |
| `GetWithProductInfo` | `GetProductInfo` |
| `GetWithNetServer` | `NetServerGetInfo` |
| `GetOSVersionFromWMI` | `Win32_OperatingSystem` through WMI |
| `GetWithKernel32` | The file version resource of `kernel32.dll` |

## Building

Windows with MSVC, since the libraries are linked through `#pragma comment`.

```sh
cmake -S . -B build
cmake --build build
```
