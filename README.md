# Riak Query Sniffer

## Description

This program uses libpcap to capture and analyze packets destined for
a Riak server.  With a variety of command line options, you can tune
the output to show you a variety of outputs to help diagnose what your
clients are doing.

There are other options useful for tuning the output to your
specifications.  Please see the application help and play with it.


## Examples

To give you a visual diagram, this is what it looks like when run on
a hypothetical machine. Note that you can run this script on a Riak
machine or on your application node depending on what you want to
analyze.

    $ sudo ./riak-sniffer  
    Initializing Riak sniffing on eth0:8087...

    2012/05/04 18:28:10 701 total queries, 63.73 per second
        7  0.64/s  get obj:\xf3\xa4\x99
        6  0.55/s  get user:234934
        6  0.55/s  get user:3723424
        6  0.55/s  get log:383443
        5  0.45/s  get log:234934
        5  0.45/s  get user:213334
        5  0.45/s  get log:213334
        5  0.45/s  put status:833334
        5  0.45/s  put user:199593
        4  0.36/s  get log:1003944

This shows you that, on this machine, you had ~64 get/put requests per
second for a total of 701 queries since you started sniffing. Then it
breaks down the top 10 by frequency and tells you if it's a get or put,
what bucket (before the colon), and which key (after the colon).

Non-printable characters are shown as hexadecimal escapes. Just to be
nice to your terminal. :)

You can also ask for it to do a realtime dump of all queries. I find
this useful for seeing what is going on realtime with a particular
bucket/key. I.e., if I want to see what queries are being executed for a
given user.

    $ sudo ./riak-sniffer  -v
    Initializing Riak sniffing on eth0:8087...
    get user:83485334
    get log:83485334
    get log:345833
    get user:345833
    put user:133432
    get user:1953900
    get status:383113

Etc.


## Building

This requires Go 1. I also assume you have $GOPATH set correctly. To
build this project, first you need the protobuf set up for Go. This is
pretty straightforward, you can get directions here:

* http://code.google.com/p/goprotobuf/

Next, you have to build and install the Riak protobufs in a Go
package. This is done like this:

    $ cd $GOPATH/src
    $ mkdir riakclient && cd riakclient
    $ wget https://raw.github.com/basho/riak-erlang-client/master/src/riakclient.proto
    $ protoc --plugin=$GOROOT/bin/protoc-gen-go --go_out=. riakclient.proto
    $ go build

If that success, now you can build the riak-sniffer:

    $ cd path-you-cloned-the-repo
    $ go build

Enjoy!


## Bugs and Improvements 

This code is housed at https://github.com/xb95/riak-sniffer and pull
requests, issues, and comments are always welcome.


## Licensing

See the LICENSE file for more information.

Written by Mark Smith <mark@qq.is> at Bump Technologies.
