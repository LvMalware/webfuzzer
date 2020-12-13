# fuzzer.pl
> A multi-threaded web fuzzer written in Perl

fuzzer.pl is a simple and fast web fuzzer with support for multiple threads and the use of filters.

This is the version 0.2, nicknamed 'Cockroach' (the versions will be named after bugs, as it will probably contain a lot of them).



## Usage

```
fuzzer.pl [option(s)] -w <wordlist> <url>

Options:

    -h, --help              Show this help message and exit
    -v, --version           Show the version and exit
    -T, --tasks             Number of tasks to run in parallel
    -t, --timeout           Timeout for each request
    -m, --methods           A comma-separated list of HTTP methods to request
    -u, --useragent         A User-Agent string (default: fuzzer.pl/0.1)
    -d, --delay             Interval in seconds to wait between requests
    -j, --json              Print each result as a JSON
    -r, --recursive         Go recursive into directories
    -w, --wordlist          The wordlist of paths to request
    -H, --headers           Define a header to be sent
    -p, --payload           Send some custom data to the server
    -f, --filter            Only display results matching with a filter
                            (See FILTERS below)
    --norecursive           Do not follow directories recursively (default)

```

## Examples

```
./fuzzer.pl -w wordlist.txt -T 16 http://example.com   
```
```
./fuzzer.pl -w wordlist.txt -d 2 -u "Googlebot/1.0" https://example.com
```
```
./fuzzer.pl -w wordlist.txt -f 'content=~/admin/i' https://example.com
```
```
./fuzzer.pl -w wordlist.txt -H DNT=1 http://example.com
```

## FILTERS

   A filter is a collection of semicolon-separated expressions that are
    tested against the result of each request. When used, only the requests 
    matching with at least one the filters will be displayed. The filters can 
    contain basic comparissions and even Perl regular expressions. Any number of
    expressions can be combined using the logic operators 'or' and 'and' to form
    a filter and multiple filters can be joined into one by using a semicolon.
    Filters can be used to validate the following fields of a response:
    
-  status  - the status code of the response (200, 301, 404, etc.)
-  content - the content returned as response by the server
-  length  - the binary length of the content (can have the value 'null')
-  url     - the url that provided the response

###    Examples of filters:
        'url =~ /.txt$/ and status != 200'
        'status == 200; content =~ /admin/i'
        'status > 300 and status < 400 or status == 200'

## Meta

Lucas V. Araujo – lucas.vieira.ar@disroot.org

Distributed under the GNU GPL license. See ``LICENSE`` for more information.

[https://github.com/LvMalware/webfuzzer](https://github.com/LvMalware/)

## Contributing

1. Fork it (<https://github.com/LvMalware/webfuzzer/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

### Foud a bug? Want some new feature? Open an issue and I will take a look.
