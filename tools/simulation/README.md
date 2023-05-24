# Simulation of `wsbrd` using `ns-3`

This project aims to run `wsbrd` inside the [`ns-3`](https://www.nsnam.org/)
simulator. It must be noted that Silicon Labs internally uses a private fork of
`ns-3` with enhancements providing an environment quite different from the
public simulator. Thus it is not recommended to experiment with this tool unless
you know what you are doing.

A shared library `libwsbrd-ns3.so` is built and can be used to simulate `wsbrd`
when paired with a simulated RCP (also private to the company).
