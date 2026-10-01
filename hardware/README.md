# Hardware benchmark (STM32F407VET6, Cortex-M4)

Files for the pqm4 benchmark of standard Kyber-1024 and P1 = (4,2,2,10,5)
(thesis Section 5.4.2 and Appendix A).

| Path | Content |
|---|---|
| `build_kyber1024_p1.sh` | Rebuilds all images from pqm4 commit `5e5cc76` |
| `hal-opencm3.patch` | Adds STM32F407VE to pqm4's board detection |
| `params_P1.patch` | P1 change in `params.h`: `KYBER_POLYVECCOMPRESSEDBYTES` k*352 -> k*320 |
| `stm32f407ve-generic.ld` | Hand-written linker script (512 KB flash, 128 KB RAM) used for all images |
| `bin/baseline/`, `bin/P1/` | Images used in the thesis (`speed_n1000.bin` = 1000 iterations) |
| `log_benchmark.py` | Captures the serial output from the board |
| `logs/` | Raw serial logs of the board runs |

Flashing: BOOT0 to 3.3 V, then
`dfu-util -a 0 -s 0x08000000:leave -D bin/P1/speed_n1000.bin`.
Clock: 24 MHz. Toolchain: arm-none-eabi-gcc 13.2.1, newlib 4.4.0.

Running `build_kyber1024_p1.sh` reproduces every image in `bin/` byte for byte.
