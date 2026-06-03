# Installation Guide

## Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libcurl4-openssl-dev libssl-dev
git clone https://github.com/Rehan137/origin-finder.git
cd origin-finder
make
./origin_finder example.com
```

## Arch Linux
```bash
sudo pacman -S gcc curl openssl
git clone https://github.com/Rehan137/origin-finder.git
cd origin-finder
make
```

## macOS
```bash
brew install curl openssl
git clone https://github.com/Rehan137/origin-finder.git
cd origin-finder
gcc -o origin_finder origin_finder.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcurl -lssl -lcrypto -lpthread -lm
```
