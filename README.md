# tdbus Prototype

## A Trusted Message Bus Built on Top of D-Bus

Source code of the prototype presented in the paper [A Trusted Message Bus Built on Top of D-Bus](http://sbseg.sbc.org.br/2020/en), presented at [20th Brazilian Symposium on Information and Computational Systems Security (SBSeg 2020)](http://sbseg.sbc.org.br/2020/en).

## Table of Contents ##
- [Abstract](#abstract)
- [Install](#install)
- [Setup](#setup)
- [Contribution guidelines](#contribution-guidelines)
- [License](#license)

## Abstract ##

A wide range of applications use Inter-Process Communication (IPC) mechanisms to communicate between each other or between their components running in different processes. A well-known IPC mechanism in UNIX-like systems is D-Bus, which allows processes to communicate by receiving and routing messages. Despite being widely used, such system lacks mechanisms to provide end-to-end data confidentiality. In this paper we propose the use of Intel Software Guard Extensions (SGX) to provide a trusted communication channel between local applications over the D-Bus message bus system. We obtained stronger security guarantees in message confidentiality and integrity while keeping a small Trusted Computing Base (TCB) and compatibility with the reference D-Bus system.

```
@INPROCEEDINGS{207522,
    AUTHOR="Newton Will and Tiago Heinrich and Amanda Viescinski and Carlos Maziero",
    TITLE="A Trusted Message Bus Built on Top of D-Bus",
    BOOKTITLE="SBSeg 2020",
    DAYS="13-16",
    MONTH="oct",
    YEAR="2020"
}
```

## Install ##

The system require D-Bus Daemon 1.12.2 and [SGX](https://github.com/intel/linux-sgx) SDK 2.9.101.2.

## Setup ##

After the requirements being install, for the server just run:
```
./test_server <trusted>
```

And, for the client:

```
./run_test.sh <trusted> <messages> <repeats> <datatype>
```

Where `<trusted>` is `0` or `1`. The `<messages>` is the amount of messages you are going to send. The `<repeats>` is the number of tests that will run, and `<datatype>` is the type of data to be sent: `1 = 1 byte`; `2 = 2 bytes`; `3 = 4 bytes`; `4 = 8 bytes`; `5 = string;` and `6 = array`.

## Contribution guidelines ##
* [newtoncw](https://github.com/newtoncw) (Newton Carlos) (owner)
* [h31nr1ch](https://github.com/h31nr1ch) (Tiago Heinrich) (contributor)
* [abviescinski](https://github.com/abviescinski) (Amanda B. Viescinski) (contributor)
* [cmaziero](https://github.com/cmaziero) (Carlos Maziero) (contributor)

## License ##

Licenced under the GPL-3.0 License. If you make any use of this code for academic purpose, you must cite the papers.
