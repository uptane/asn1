```Bash
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
# This is how to convert TUF metadata back and forth.
# Copy timestamp.json from somewhere (e.g., https://github.com/theupdateframework/tuf/blob/develop/examples/repository/metadata/timestamp.json).
$ ./README.py
# This is how to convert the time server metadata back and forth.
$ ./timeservermetadata.py
```

All metadata are encoded using BER for simplicity in decoding.
