# Mr hyde

![Photo by Henry Van der Weyde (1838-1924) / Public Domain](https://github.com/rafael-santiago/mr-hyde/blob/master/etc/Jekyll-mansfield.jpg "Photo by Henry Van der Weyde (1838-1924) / Public Domain")

## What is this?

This repository gathers some sub-projects related with steganography. Here I am avoiding cliché things like
steganography using images and sounds.

Take a look at each sub-project's ``README.md`` to know more details about the related sub-project.

**WARNING**: Never use steganography to protect things. Do not be silly. Instead of hiding you must encrypt it.
If possible using zillions of cryptographic layers with zillions of keys and after hide it if you still want to.
Maybe you should use two or more steganographic layers... I think it would be cool but a paranoic nightmare for
the curious people.

## How to clone this repo?

This repo has some submodules so after the ``git-clone`` command you also need to init its submodules. Take a look:

```
doctor@TARDIS:~/github# git clone https://github.com/rafael-santiago/mr-hyde
doctor@TARDIS:~/github# cd mr-hyde
doctor@TARDIS:~/github/mr-hyde# git submodule update --init
```

Now this repo is ready for the build stage.

## The build stage

In order to build the sub-projects implemented here you need to use [Hefesto](https://github.com/rafael-santiago/hefesto).
Once Hefesto installed and working on your system, you need to install the extension ``forge-bootstrapper``. To install
it you need to clone [Helios](https://github.com/rafael-santiago/helios). Following, you get the exact steps for installing
the ``forge-bootstrapper``:

```
doctor@TARDIS:~/github# git clone https://github.com/rafael-santiago/helios helios
doctor@TARDIS:~/github# cd helios
doctor@TARDIS:~/github/helios# hefesto --install=forge-bootstrapper
```

All done here, now your ``Hefesto``'s installed copy know how to run recursive forges.

Backing to the ``mr-hyde``, just move to the ``mr-hyde src's`` toplevel sub-directory and call for ``Hefesto`` from there:

```
doctor@TARDIS:~/github/mr-hyde/src# hefesto
```

A recursive forge will be started and after you will get all binaries that you need inside the ``../bin`` path.

If for some reason you want to run only a specific sub-project's forge you need to invoke ``hefesto`` being inside the
wanted sub-project's ``src`` sub-directory:

```
doctor@TARDIS:~/github/mr-hyde# cd src/lit/src
doctor@TARDIS:~/github/mr-hyde/src/lit/src# hefesto
```

In the same way you will get this binary inside ``../../../bin`` sub-directory.

I must confess that I did not write this thinking about plush ``Windows`` boxes, so good luck for you kid!
