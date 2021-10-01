# r2flutch
Yet another tool to decrypt iOS apps using r2frida.

<iframe width="560" height="315" src="https://www.youtube.com/embed/dJMPDYs_KIw" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

![Demo](img/download.png)


## Requirements

It requires to install Frida on the Jailbroken iOS device:

 * Jailbroken device
 * Frida installed on the device. (e.g. via Cydia) https://frida.re/docs/ios/#with-jailbreak
 * radare2 installed. https://github.com/radareorg/radare2


## Installation

* Using PIP:

```
pip install r2flutch
```

* Using r2pm

```
r2pm -ci r2flutch
```

## Usage

* Run `r2flutch -l` to list all the installed apps.

![List applications](img/list_apps.png)


* Run `r2flutch -i <App Bundle>` to pull a decrypted IPA from the device.

![List applications](img/demo.png)

* Run `r2flutch <App Bundle>` to pull the decrypted app binary from the device.
