# mop

This tool performs steganography using ``pcap`` files.

The name is originated from a lousy acronym: ``m``ore ``o``ver [this] ``p``cap.

## Usage

The usage is simple. The ``mop`` works based on two tasks:

- hide
- recover

You need to specify it with the option ``--task``. For instance:

```
doctor@TARDIS:~/src/mop/sample# ./mop --task=hide
```

Depending on the chosen task some additional options are required.

### Hiding things

This is the command that you need to use:

```
doctor@TARDIS:~/src/mop/sample# ./mop --task=hide --pcap-file=cover.pcap --input-buf="secret message." --output-pcap-file=hidden-data.pcap
```

According to the previous sample the ``--pcap-file`` option specifies the cover pcap that will be used.
The ``--input-buf`` specifies the message that must be hidden.
The ``--output-pcap-file`` specifies the path of the output ``pcap`` file that will be contain the hidden message.

Instead of specifying the message data you can load it from a file using the option ``--input-file=<filepath>``.

You can use several tools in order to generate your cover ``pcap`` files. The ``tcpdump`` and ``wireshark`` are good
tools where this kind of file can be generated.

### Recovering hidden things

This is the command that you need to use:

```
doctor@TARDIS:~/src/mop/sample# ./mop --task=recover --pcap-file=hidden-pcap.pcap
```

You just need to specify the ``pcap`` which contains the hidden data using the ``--pcap-file`` option. By default the data is
dumped to the ``stdout``. However, if you prefer to dump the resultant buffer into a file you should use the option
``--output-file=<filepath>``.
