# Riak Query Sniffer

## Description

This program uses libpcap to capture and analyze packets destined for
a Riak server that is using the protobuf API. This tool helps diagnose
what queries are being sent to your database.

You can either output the data raw or you can aggregate it to get an
idea of what's going on. Show popular queries, clients, buckets, keys,
etc.

Read on to see some examples of what this tool can tell you.


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


## Format Strings

There are many ways of slicing your data. Each query that is intercepted
has certain bits of data and you can output only the bits you care
about. You can use this to answer different kinds of questions depending
on what your needs are.

Think of this like a printf string, except instead of you supplying the
arguments you just tell us what you want to see and we make it happen.

    #k       The key being accessed.
    #b       The bucket being accessed.
    #s       The "IP:PORT" of the remote end of the query. (Source.)

For example, you can use these to ask "what buckets are most popular" by
doing something like this:

    $ sudo ./riak-sniffer -f '#b'

The output will only show buckets. Keys and sources will be ignored. Or,
if you want to break everything down and see if you're getting swamped
by one host sending the same query:

    $ sudo ./riak-sniffer -f '#s #b:#k'

The output will look like "10.3.4.53:38333 foo:somekey" and you can
easily tell if someone is misbehaving egregiously.


## Building

This requires Go 1. Building and using this project should be a simple as:

    $ go get github.com/xb95/riak-sniffer
    $ go install github.com/xb95/riak-sniffer

This package bundles the Riak protobufs. They are slightly hand-modified
to build them into a single package.


## Bugs and Improvements 

This code is housed at https://github.com/xb95/riak-sniffer and pull
requests, issues, and comments are always welcome.


## Licensing

See the LICENSE file for more information.

Written by Mark Smith <mark@qq.is> at Bump Technologies.
