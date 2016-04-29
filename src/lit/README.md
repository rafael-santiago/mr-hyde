# lit

``lit`` is a lousy acronym for ``l``ook ``i``nside ``t``ard. This program uses blank spaces at the end of innocent text lines
to hide things. The best thing to do here is to use free Books as a cover. Maybe here we have a literary steganography :)
Beware that it is not a good idea transmit your steganogram printed ;)

## Usage

Simple goal, simple usage.

To hide you should do it:

```
you@SOMEWHERE:/over/the/rainbow# ./lit --task=hide --input-buf="Muttley, do something..." --cover-file=books/moby-dick.txt --output-file=moby-nasty-dick.txt
```

You can also specify the input buffer from a filepath:

```
you@SOMEWHERE:/overr/the/rainbow# ./lit --task=hide --input-file=nasty-encripted-elf --cover-file=books/mody-dick.txt --output-file=nasty-moby-dick.txt
```

To recover hidden things you should do it:

```
you@SOMEWHERE:/over/the/rainbow# ./lit --task=recover --input-file=moby-nasty-dick.txt
```

The hidden stuff will be always dumped to the ``stdout``. So, if you want this data dumped to another place use:

```
you@SOMEWHERE:/over/the/rainbow# ./lit --task=recover --input-file=nasty-moby-dick.txt --output-file=nasty-encripted-elf
```

As it had been said: simple!
