# tdbus Prototype

## A Trusted Message Bus Built on Top of D-Bus

Source code of the prototype presented in the paper [A Trusted Message Bus Built on Top of D-Bus](http://sbseg.sbc.org.br/2020/en), presented at [20th Brazilian Symposium on Information and Computational Systems Security (SBSeg 2020)](http://sbseg.sbc.org.br/2020/en).

### Abstract
A wide range of applications use Inter-Process Communication (IPC) mechanisms to communicate between each other or between their components running in different processes. A well-known IPC mechanism in UNIX-like systems is D-Bus, which allows processes to communicate by receiving and routing messages. Despite being widely used, such system lacks mechanisms to provide end-to-end data confidentiality. In this paper we propose the use of Intel Software Guard Extensions (SGX) to provide a trusted communication channel between local applications over the D-Bus message bus system. We obtained stronger security guarantees in message confidentiality and integrity while keeping a small Trusted Computing Base (TCB) and compatibility with the reference D-Bus system.

## License

Licenced under the GPL-3.0 License. If you make any use of this code for academic purpose, you must cite the papers.
