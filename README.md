# AESPonyfill

[Ponyfill](https://ponyfill.com/) for AES encryption/decryption to use when (and preferably only when) the SubtleCrypto API is not available.

> ### NOTE
> To clone the repo, use:
> 
> **`git clone https://git.xeaf.dev/xeaf/AESPonyfill --recursive`**
> 
> If you do not use `--recursive`, the Git submodules won't be downloaded, and building will be impossible.
> 
> If you already made a clone, you can download the Git submodules like so:
> 
> `git submodule update --init --recursive`

## Demo

You **can simply double-click the HTML file** to load the demo, or **run a local webserver that serves the current directory** via `python3 -m http.server 8080`.
Remember, you still need to **build the bundle first** and **place the minified version in the same directory as the HTML**.
You can download the **prebuilt bundle** from the "Releases" tab, or build it yourself by running `bash build.sh` which will do (almost) everything necessary.

> ### NOTE
> Building on Windows is **not supported**.
> Please use **WSL** instead.