from .cli import main

if __name__ == '__main__':      # serve()'s analysis worker (folderwork.py) imports this module again as __mp_main__: it must not run the CLI
    raise SystemExit(main())
