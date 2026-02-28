#!/usr/bin/env bash

# Make sure user is using Bash for EMSDK to work
if [ -z "$BASH_VERSION" ]; then
  echo >&2 "Please use Bash to run this script. (else EMSDK won't work)"
  exit 1
fi

# Check if Git is installed
command -v git >/dev/null 2>&1 || { echo >&2 "git is not installed. Aborting."; exit 1; }

# Checkout the submodules
git submodule update --recursive

# Sets up Emscripten SDK.
cd emsdk
git pull
chmod +x emsdk
echo "Downloading Emscripten SDK..."
./emsdk install latest 2>&1 >/dev/null
./emsdk activate latest 2>&1 >/dev/null
EMSDK_QUIET=1 source ./emsdk_env.sh
cd ..

# Now check if everything else is available
command -v em++ >/dev/null 2>&1 || { echo >&2 "Emscripten is not installed. Aborting."; exit 1; }
command -v node >/dev/null 2>&1 || { echo >&2 "Node.js is not installed. Aborting."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo >&2 "npm is not installed. Aborting."; exit 1; }
command -v npx >/dev/null 2>&1 || { echo >&2 "npx is not installed. Aborting."; exit 1; }

# Pulls the latest version of CryptoPP
cd cryptopp
git pull
cd ..

# Check for ignore compilation flag
flag=false

for arg in "$@"; do
    if [[ "$arg" == "--no-rebuild" ]]; then
        flag=true
        break
    fi
done

if $flag; then
    echo "Skipping rebuilding, will use old output files."
else
    echo "Rebuilding... (this might take a long time)"

    # Compile to a self-contained WASM+JS
    em++ wrapper.cpp cryptopp/*.cpp -O3 \
        -s WASM=1 \
        -s MODULARIZE=1 \
        -s EXPORT_NAME=AESPonyfill \
        -s SINGLE_FILE=1 \
        -s EXPORTED_FUNCTIONS='["_aes_encrypt","_aes_decrypt","_malloc","_free"]' \
        -s EXPORTED_RUNTIME_METHODS='["cwrap","ccall","HEAPU8","UTF8ToString","lengthBytesUTF8","stringToUTF8"]' \
        -o output.wasm.js

    # Compile to a self-contained ASMJS+JS
    em++ wrapper.cpp cryptopp/*.cpp -O3 \
        -s WASM=0 \
        -s MODULARIZE=1 \
        -s LEGACY_VM_SUPPORT=1 \
        -s EXPORT_NAME=AESPonyfill \
        -s EXPORTED_FUNCTIONS='["_aes_encrypt","_aes_decrypt","_malloc","_free"]' \
        -s EXPORTED_RUNTIME_METHODS='["cwrap","ccall","HEAPU8","UTF8ToString","lengthBytesUTF8","stringToUTF8"]' \
        -o output.asm.js
fi

# Merge all files into a single bundle
node combine.js wrapper.js output.wasm.js output.asm.js > output.bundle.js

# Download UglifyJS for minification
npm install uglify-js

# Minify the bundle
echo "Minifying bundle for production use... (this might take a long time)"
npx uglifyjs output.bundle.js -c -m --ie --v8 --webkit -o output.bundle.min.js
