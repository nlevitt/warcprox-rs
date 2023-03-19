# Warcprox-rs - WARC writing MITM HTTP/S proxy

<a href="https://github.com/nlevitt/warcprox-rs/actions">
  <img alt="tests" src="https://github.com/nlevitt/warcprox-rs/actions/workflows/tests.yml/badge.svg"/>
</a>

Warcprox-rs aims to be a faster clone of <a 
href="https://github.com/internetarchive/warcprox">warcprox</a>, written in rust, with some features omitted.

```
Usage: warcprox-rs [OPTIONS]

Options:
  -p, --port <PORT>                    [default: 8000]
  -b, --address <ADDRESS>              [default: localhost]
  -c, --cacert <CA_CERT>               CA certificate file. If it does not exist, it will be created [default: ./warcprox-rs-ca.pem]
  -z, --gzip                           Write gzip-compressed warc records
      --warc-filename <WARC_FILENAME>  Define custom WARC filename using variables {timestamp14}, {timestamp17}, {serialno}, {randomtoken}, {hostname}, {port}, {maybe_dot_gz} [default: warcprox-{timestamp17}-{serialno}-{randomtoken}.warc{maybe_dot_gz}]
  -h, --help                           Print help
  -V, --version                        Print version
```