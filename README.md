
CBC maleability in the context of Efail
=======================================

This repository is part of a report I need to write for uni. It can be used to
explore the maleability of CBC mode block ciphers. This is critical to
understanding the [Efail vulnerability](https://efail.de).


Usage
-----

This was developed using python `3.8.2` on a GNU/Linux system. It should work
with many other versions of python though. To simply run the "exploit", run
`make` or `python main.py`. But of course the actual purpose of this repository
is to provide an understanding of the concepts.

Code layout
-----------

The code is divided into two files:

- `cbc.py`: Provides a library to do simple to follow (but very insecure!) basic
  CBC mode encryption (It actually uses ROTn, so it is really just meant for
  exploration)
- `main.py`: Defines a ciphertext to interact with, a class for CBC Gadgets and
  a "replace" function using a CBC Gadget to exploit the maleabiltiy of CBC.
