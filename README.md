# com.7theta/clj-nmap

[![Current Version](https://img.shields.io/clojars/v/com.7theta/clj-nmap.svg)](https://clojars.org/com.7theta/clj-nmap)
[![GitHub license](https://img.shields.io/github/license/7theta/clj-nmap.svg)](LICENSE)
[![Circle CI](https://circleci.com/gh/7theta/clj-nmap.svg?style=shield)](https://circleci.com/gh/7theta/clj-nmap)
[![Dependencies Status](https://jarkeeper.com/7theta/clj-nmap/status.svg)](https://jarkeeper.com/7theta/clj-nmap)

Clojure wrapper for the `nmap` command line tool.

## Usage

The `clj-nmap.core` provides the `nmap` function that can be called
using the same parameters as the command line tool.

```clj
(require '[clj-nmap.core :refer [nmap]])

(nmap "-T4" "-A" "10.10.0.1")
```

## Copyright and License

Copyright © 2017 7theta

Distributed under the Eclipse Public License.

