# Syscalls

Tool to generate system call tables from the linux source tree.

## Example

The following will produce a markdown (.md) file containing the tables for all supported
architectures:

```sh
python3 -m syscalls -p ~/Downloads/linux -f md -o ./syscalls/build/SPEC.md
```

## Tables

Pre-generated tables can be found in the [tables](tables) directory.

## Roadmap

* Searchable site [ ]
* Parse and hotlink struct definitions [ ]
* Validation/testing against common table definitions [ ]
