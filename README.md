# Router Data Plane #

This project contains the implementation of a router's data plane. It uses
ethernet at the data-link layer and IP at the network layer. Also, ARP is implemented
and ICMP support is provided.

My most important contribution is the code from `router.c`.

## Usage ##
After building, the router program can be started with:
```
./router <FILE> # FILE contains a static ARP table
```

## Performance ##
The route table search is realised in O(log n), by using a trie structure to store
the table lines.