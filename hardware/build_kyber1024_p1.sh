#!/bin/bash
# build_kyber1024_p1.sh
# Rebuilds the pqm4 ML-KEM-1024 (m4fspeed) images used in the thesis for
#   - the standard Kyber-1024 baseline (du=11, dv=5, ct = 1568 B)
#   - P1 = (4,2,2,10,5)              (du=10, dv=5, ct = 1440 B)
# on a generic STM32F407VET6 board.
#
# Tested with arm-none-eabi-gcc 13.2.1 (Ubuntu 24.04). Run from this folder.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"

# ---- 1. toolchain (skip if already installed) ----
sudo apt-get install -y --no-install-recommends \
    gcc-arm-none-eabi libnewlib-arm-none-eabi qemu-system-arm

# ---- 2. clone pqm4 at the exact commit used in the thesis ----
git clone https://github.com/mupq/pqm4.git
cd pqm4
git checkout 5e5cc76
git submodule update --init mupq libopencm3      # pinned commits
(cd mupq && git submodule update --init pqclean)

# ---- 3. board support for the STM32F407VE ----
patch -p0 < "$HERE/hal-opencm3.patch"
cp mk/stm32f4discovery.mk mk/stm32f407ve-generic.mk
sed -i 's/DEVICE=stm32f407vg/DEVICE=stm32f407ve/' mk/stm32f407ve-generic.mk
# hand-written linker script (512 KB flash, 128 KB RAM); pqm4 picks up
# ldscripts/$PLATFORM.ld automatically instead of generating one
cp "$HERE/stm32f407ve-generic.ld" ldscripts/
PLATFORM=stm32f407ve-generic
SCHEME=crypto_kem_ml-kem-1024_m4fspeed
PARAMS=crypto_kem/ml-kem-1024/m4fspeed/params.h

build () {   # $1 = output folder
  mkdir -p "$1"
  rm -rf obj elf bin
  make -j2 PLATFORM=$PLATFORM \
    bin/${SCHEME}_test.bin bin/${SCHEME}_speed.bin bin/${SCHEME}_stack.bin
  cp bin/${SCHEME}_*.bin "$1/"
  # speed image with 1000 iterations (used for the cycle-count tables)
  rm -rf obj elf bin
  make -j2 PLATFORM=$PLATFORM MUPQ_ITERATIONS=1000 bin/${SCHEME}_speed.bin
  cp bin/${SCHEME}_speed.bin "$1/speed_n1000.bin"
}

# ---- 4. standard Kyber-1024 ----
build "$HERE/out/baseline"

# ---- 5. P1: KYBER_POLYVECCOMPRESSEDBYTES k*352 -> k*320 (du 11 -> 10) ----
patch "$PARAMS" < "$HERE/params_P1.patch"
build "$HERE/out/P1"

echo "Done. Images in $HERE/out/baseline and $HERE/out/P1"
