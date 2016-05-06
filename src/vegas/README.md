# vegas

``vegas`` is a tool that uses ``Ansi Color Coding`` to hide things. As a result you can get a stupid ``hyper-colored`` output.
Let's use this bluff to hide things.

## Usage

To hide you should:

```
you@SOMEWHERE:/over/the/rainbow# ./vegas --task=hide --input-buf="Meet me at the dawn" --cover-buf="how doth the little crocodile, improve his shining tail, and pour the waters of the Nile on every golden scale... how cheerfully he seems to grin, how neatly spreads his claws, and welcomes little fishes in, with gently smiling jaws."
```

You can also specify the input buffer using ``--input-file=<filepath>`` option. Similar, you can use the ``--cover-file=<filepath>`` option to specify the cover file.

The steganogram is always dumped to the ``stdout``, so you should to redirect it to a file:

```
you@SOMEWHERE:/over/the/rainbow# ./vegas --task=hide --input-buf="Meet me at the dawn" --cover-file="How-doth-the-little-crocodile.txt" > carroll_poem.txt
```

Now supposing that your hidden message is inside ``carroll_poem.txt`` file and you want to recover it. You should try:

```
you@SOMEWHERE:/over/the/rainbow# ./vegas --task=recover --input-file=carroll_poem.txt
```

You will see the hidden message at your terminal screen.

All done. Now you master this tool.
