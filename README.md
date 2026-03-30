# r2flutch

Yet another tool to decrypt iOS apps using r2frida.

## Requirements

- Jailbroken iOS device
- [Frida](https://frida.re/docs/ios/#with-jailbreak) installed on the device (e.g. via Cydia/Sileo)
- [radare2](https://github.com/radareorg/radare2) installed on the host
- [r2frida](https://github.com/nowsecure/r2frida) installed on the host
- Python >= 3.6
- Node.js >= 20 (for the r2frida agent plugin)

## Installation

### From pip

```bash
pip install r2flutch
```

### From r2pm

```bash
r2pm -ci r2flutch
```

### From source

```bash
git clone https://github.com/as0ler/r2flutch.git
cd r2flutch
pip install -r requirements.txt
pip install -e .
```

After installing, build the r2frida agent dependencies:

```bash
cd r2flutch/agent
npm install
```

> **Note:** The `npm install` step is required so that the TypeScript plugin can
> resolve `frida-objc-bridge` at runtime. Without it, r2frida will fail to
> compile the plugin and all decryption commands will be unavailable.

## Usage

> **Note:** The default transport is **SSH**, which requires a `config.json`
> file with device credentials (see [SSH Transport](#ssh-transport-default)
> below). To use the original Frida-based transfer without a config file, add
> `-t frida` to any command.

### List installed applications

```bash
r2flutch -l
```

```
Bundle Identifier                  Name
----------------------------------------------------
com.aimharder.mainapp              AimHarder
com.apple.AppStore                 App Store
com.apple.calculator               Calculator
com.apple.camera                   Camera
com.apple.mobilesafari             Safari
...
43 applications found
```

The list is sorted alphabetically by bundle identifier and includes the
application display name. No SSH connection or config file is needed for this
command.

### Decrypt an app and generate an IPA

```bash
r2flutch -i com.aimharder.mainapp
```

```
[ℹ] SSH connection established to root@127.0.0.1:2222
[ℹ] Open Application Process com.aimharder.mainapp
Listing application content: 100%|███████████████| 1528/1528 [00:02<00:00, 615files/s]
[ℹ] Loading all modules
[ℹ] Decrypting module AimHarder
[ℹ] Module AimHarder decrypted successfully
Copying application bundle: 100%|████████████████| 1206/1206 [00:11<00:00, 106file/s]
[ℹ] Creating IPA file at ./AimHarder.ipa
[ℹ] IPA file saved at ./AimHarder.ipa
[✓] SUCCESS - r2flutch Decryption Complete!
```

### Decrypt the binary only (no IPA)

```bash
r2flutch com.aimharder.mainapp
```

The decrypted binary is saved to the current directory. Use `-o` to change the
output location:

```bash
r2flutch -o /tmp/decrypted com.aimharder.mainapp
```

### Use Frida transport (no config file needed)

```bash
r2flutch -t frida -i com.aimharder.mainapp
```

### Debug mode

Pass `-d` to see detailed internal messages (memory offsets, temp paths,
library loading, patching details):

```bash
r2flutch -d -i com.aimharder.mainapp
```

## File Transfer Transport

r2flutch supports two transport modes for downloading files from the device:

| Flag | Transport | Description |
|------|-----------|-------------|
| `-t ssh` | **SSH (default)** | Downloads files over SFTP. Faster and more reliable for large bundles. |
| `-t frida` | Frida | Downloads files through r2frida commands (original behavior). |

### SSH Transport (default)

SSH transport requires a `config.json` file with the device credentials:

```json
{
    "ssh": {
        "host": "192.168.1.100",
        "port": 22,
        "username": "root",
        "password": "alpine"
    }
}
```

The fields `host`, `username` and `password` are **required**. `port` defaults
to `22` if omitted.

By default r2flutch looks for `config.json` in the current directory. Use `-c`
to specify a custom path:

```bash
r2flutch -c /path/to/config.json -i com.example.app
```

A sample config file is provided at `config.json.example`.

### Frida Transport

To use the original Frida-based file transfer (no config file needed):

```bash
r2flutch -t frida -i com.example.app
```

## All Options

```
usage: r2flutch [-h] [-d] [-o OUTPUT] [-i] [-l] [-t {ssh,frida}] [-c CONFIG] [target]

r2flutch (by Murphy)

positional arguments:
  target                          Bundle identifier of the target app

options:
  -h, --help                      show this help message and exit
  -d, --debug                     Show debug messages
  -o OUTPUT, --output OUTPUT      Path where output files will be stored.
  -i, --ipa                       Generate an IPA file
  -l, --list                      List the installed apps
  -t {ssh,frida}, --transport     Transport for file transfer: ssh (default) or frida
  -c CONFIG, --config CONFIG      Path to config.json file (default: config.json)
```

## Testing

Run the test suite with coverage:

```bash
bash run_tests.sh
```

Or directly with pytest:

```bash
python3 -m pytest test/ -v
```

## Troubleshooting

### Xcode isn't open

```
error: This feature requires an iOS Developer Disk Image to be mounted;
run Xcode briefly or use ideviceimagemounter to mount one manually
```

**Solution:** Open Xcode and let it detect the connected device.

### Frida Gadget isn't installed

```
error: Cannot attach: Need Gadget to attach on jailed iOS;
its default location is: ~/.cache/frida/gadget-ios.dylib
```

**Solution:** Download the gadget from the
[Frida releases](https://github.com/frida/frida/releases) page and place it in
the expected path:

```bash
curl -L https://github.com/frida/frida/releases/download/<VERSION>/frida-gadget-<VERSION>-ios-universal.dylib.gz \
  -o gadget.dylib.gz
gunzip gadget.dylib.gz
mkdir -p ~/.cache/frida
mv gadget.dylib ~/.cache/frida/gadget-ios.dylib
```

### Plugin fails to compile (`Cannot resolve "frida-objc-bridge"`)

```
ERROR: plugin.ts:10:17: Could not resolve "frida-objc-bridge"
ERROR: r2frida-compile: Compilation failed
```

**Solution:** Install the agent dependencies:

```bash
cd r2flutch/agent
npm install
```
