#!/usr/bin/env perl

use JSON;
use strict;
use threads;
use warnings;
use Thread::Queue;
use WWW::Curl::Easy;
use Getopt::Long qw(:config no_ignore_case);
use HTTP::Status qw(:constants :is status_message);

sub version
{
    print "$0 v0.2 (Cockroach)\n";
    exit 0;
}

my $wordlist_queue = Thread::Queue->new();
my $backup_queue   = Thread::Queue->new();
my $recursive      = 0;

my $add_dir_lock     :shared;
my @target_dirs      :shared;
my @proxy_list       :shared;

sub fuzzer_loop
{
    my ($thr, $target, $headers, $methods, $timeout,
        $filter, $json, $ua, $payload, $delay) = @_;
    my $curl = WWW::Curl::Easy->new();

    $curl->setopt(CURLOPT_HEADER, 0);
    $curl->setopt(CURLOPT_USERAGENT, $ua);
    $curl->setopt(CURLOPT_TIMEOUT, $timeout);
    $curl->setopt(CURLOPT_FOLLOWLOCATION, 1);
    $curl->setopt(CURLOPT_HTTPHEADER, $headers)
    $curl->setopt(CURLOPT_READDATA, \$payload) if $payload;
    
    my @req_methods = split /,/, $methods;

    while (defined(my $resource = $wordlist_queue->dequeue()))
    {
        next unless $resource;

        $backup_queue->enqueue($resource);
        my $full_path = $target . $resource;
        substr($full_path, 9) =~ s/\/\/+/\//g;

        $curl->setopt(CURLOPT_URL, $full_path);

        for my $met (@req_methods)
        {
            $curl->setopt(CURLOPT_CUSTOMREQUEST, $met);
            my $content;
            
            my $proxy = $proxy_list[rand @proxy_list] if @proxy_list;
            $curl->setopt(CURLOPT_PROXY, $proxy) if $proxy;
            $curl->setopt(CURLOPT_WRITEDATA, \$content);
            next if $curl->perform() != 0;
            my $url    = $curl->getinfo(CURLINFO_EFFECTIVE_URL);
            my $status = $curl->getinfo(CURLINFO_RESPONSE_CODE);
            my $length = length($content);
            my $reason = status_message($status);
            if ($recursive && $status == 200 && $met eq 'GET' && $url =~ /\/$/)
            {
                lock($add_dir_lock);
                push @target_dirs, $full_path;
            }

            if ($filter)
            {
                my $match = 0;
                for my $rule (split /;/, $filter)
                {
                    $rule =~ s/$_/\$$_/g for qw(length status content url);
                    next if ($rule =~ /content/ && !$content);
                    # NEVER use eval() like this in production code
                    if (eval($rule))
                    {
                        $match = 1;
                        last;
                    }
                }
                next unless $match == 1;
            }

            if ($json)
            {
                print encode_json({
                    status   => $status,
                    length   => $length,
                    reason   => $reason,
                    url      => $url,
                    method   => $met,
                }) . "\n";
            }
            else
            {
                print "[$status] URL: $url | Method: $met | Reason: " .
                      "$reason | Length: $length\n";
            }
            sleep($delay);
        }
    }
}

sub help
{
    print <<HELP;

fuzzer.pl - A multi-threaded web fuzzer written in Perl

Usage: fuzzer.pl [option(s)] -w <wordlist> <url>

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
    -H, --header            Define a header to be sent ("header: value")
    -p, --payload           Send some custom data to the server
    -P, --add-proxy         Add a proxy to be used to requests
                            (See PROXY below)
    -f, --filter            Only display results matching with a filter
                            (See FILTERS below)
    --test-proxy            Test all proxy server before using them
    --norecursive           Do not follow directories recursively (default)

    Examples:
        ./fuzzer.pl -w wordlist.txt -T 16 http://example.com/
        ./fuzzer.pl -w wordlist.txt -d 2 -u "Googlebot/1.0" https://example.com/
        ./fuzzer.pl -w wordlist.txt -f 'content=~/admin/i' https://example.com/
        ./fuzzer.pl -w wordlist.txt -H "DNT: 1" http://example.com/
        ./fuzzer.pl -w wordlist.txt -P socks5://127.0.0.1:9050 https://example.com/

FILTERS:

        A filter is a collection of semicolon-separated expressions that are
    tested against the result of each request. When used, only the requests 
    matching with at least one the filters will be displayed. The filters can 
    contain basic comparissions and even Perl regular expressions. Any number
    of expressions can be combined using the logic operators 'or' and 'and' to
    form a filter and multiple filters can be joined into one using semicolon.
        Filters can be used to validate the following fields of a response:
        
        status  - the status code of the response (200, 301, 404, etc.)
        content - the content returned as response by the server
        length  - the binary length of the content
        url     - the url that provided the response

    Examples of filters:
        'url =~ /.txt\$/ and status != 200'
        'status == 200; content =~ /admin/i'
        'status > 300 and status < 400 or status == 200'

PROXY:

    You can add multiple proxy servers, by using multiple instances of
    -P/--proxy and a random proxy will be selected for each request.
    The accepted proxy format is PROXY-TYPE://ADDRESS:PORT
    Example:

        SOCKS5://127.0.0.1:9050
        HTTP://127.0.0.1:8118
        HTTPS://ip.ad.dr.ess:port

HELP
    exit 0;
}

sub proxy_test
{
    return unless @proxy_list;
    my $curl = WWW::Curl::Easy->new();
    my $response;
    $curl->setopt(CURLOPT_URL, "https://api.myip.com/");
    $curl->setopt(CURLOPT_WRITEDATA, \$response);
    print "Getting real IP address (no proxy)...\n";
    my $real_ip;
    unless ($curl->perform())
    {
        my $info = decode_json($response);
        $real_ip = $info->{ip};
        print "Your IP: $real_ip\n";
        print "Country: $info->{country} ($info->{cc})\n";
    }
    else
    {
        print "Can't connect to API to retrieve your IP...\n";
        print "Are you connected to the internet?\n";
        exit;
    }
    for my $i (0 .. @proxy_list - 1)
    {
        $response = "";
        my $proxy = $proxy_list[$i];
        print "Testing $proxy ...\n";
        $curl->setopt(CURLOPT_PROXY, $proxy);
        unless ($curl->perform())
        {
            my $info = decode_json($response);
            print "Proxy IP: $real_ip\n";
            print "Country: $info->{country} ($info->{cc})\n";
            if ($info->{ip} eq $real_ip)
            {
                print "WARNING: This proxy is not hiding your IP address!\n";
                print "Removing it now...";
                delete $proxy_list[$i];
            }
            else
            {
                print "INFO: Seems good...\n";
            }
        }
    }
}

sub main
{
    my ($timeout, $tasks, $json, $delay) = (5, 10, undef, 0);
    my ($useragent, $filter, $payload, $testprx) = ("fuzzer.pl/0.2", "", "", 0);
    my $methods = "GET,POST,PUT,DELETE,HEAD,TRACE,PATCH,OPTIONS,PUSH";
    my @headers;
    my $wordlist;

    GetOptions(
        "h|help"            => \&help,
        "j|json"            => \$json,
        "t|tasks=i"         => \$tasks,
        "d|delay=i"         => \$delay,
        "v|version"         => \&version,
        "test-proxy"        => \$testprx,
        "f|filter=s"        => \$filter,
        "p|payload=s"       => \$payload,
        "T|timeout=i"       => \$timeout,
        "m|methods=s"       => \$methods,
        "H|headers=s@"      => \@headers,
        "w|wordlist=s"      => \$wordlist,
        "r|recursive!"      => \$recursive,
        "u|useragent=s"     => \$useragent,
        "P|add-proxy=s@"    => \@proxy_list,
    ) || help();

    my $target = shift @ARGV;
    die "[!] No target specified!" unless $target;
    die "[!] No wordlist specified!" unless $wordlist;

    $target .= "/" if ($target =~ tr/\///) == 2;

    if ($testprx)
    {
        if (@proxy_list)
        {
            proxy_test();
            unless (@proxy_list)
            {
                print "None of the supplied proxies seem to work. Aborting...\n";
                print "If you want to perform fuzzing even without a proxy, run" .
                " the command again without -P or --add-proxy option.\n";
                exit;
            }
            print @proxy_list + 0 ." of the proxy servers are working.\n";
            print "Starting the fuzzing process now...\n\n";
        }
        else
        {
            print "No proxy to be tested...\n";
            exit;
        }
    }

    open my $list, "<$wordlist" || die "[!] Can't open $wordlist for reading";
    while (<$list>)
    {
        chomp;
        $wordlist_queue->enqueue($_);
    }
    $wordlist_queue->end();

    push @target_dirs, $target;
    
    while (@target_dirs)
    {
        $target = shift @target_dirs;
        async {
            foreach (0 .. $tasks - 1)
            {
                threads->create('fuzzer_loop', $_, $target, \@headers, $methods,
                    $timeout, $filter, $json, $useragent, $payload, $delay
                );
            }
        };
        #a busy loop can be bad, but hell... we would need to  wait anyway
        while (threads->list(threads::running) > 0) {};
        map { $_->join() } threads->list(threads::all);
        $backup_queue->end();
        $wordlist_queue = $backup_queue;
        $backup_queue = Thread::Queue->new();
    }
    0;
}

exit main();
