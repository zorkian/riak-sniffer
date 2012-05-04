# Riak Query Sniffer

## Description

This program uses libpcap to capture and analyze packets destined for a
Riak server.  With a variety of command line options, you can tune the
output to show you a variety of outputs, such as:

    * top N queries since you started running the program
    * top N queries every X seconds (sliding window)
    * all queries (sanitized or not)

There are other options useful for tuning the output to your
specifications.  Please see the application help and play with it.


## Building

I assume you have $GOPATH set correctly. To build this project, first
you need the protobuf set up for Go. This is pretty straightforward, you
can get directions here:

    http://code.google.com/p/goprotobuf/

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
