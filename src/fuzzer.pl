#!/usr/bin/env perl

use JSON;
use strict;
use threads;
use warnings;
use HTTP::Tiny;
use Getopt::Long qw(:config no_ignore_case);
use Thread::Queue;

sub version
{
    print "$0 v0.1 (Cockroach)\n";
    exit 0;
}

my $wordlist_queue = Thread::Queue->new();
my $backup_queue = Thread::Queue->new();
my $recursive = 1;
my $add_dir_lock :shared;
my @target_dirs :shared;

sub fuzzer_loop
{
    my ($thr, $target, $headers, $methods, $timeout,
        $filter, $json, $ua, $payload, $delay) = @_;
    my $http = HTTP::Tiny->new('agent' => $ua, timeout => $timeout);
    my @req_methods = split /,/, $methods;
    my $options = {
        headers => $headers,
        content => $payload,
    };
    while (defined(my $resource = $wordlist_queue->dequeue()))
    {
        $backup_queue->enqueue($resource);

        my $full_path = $target . "/" . $resource;
        substr($full_path, 9) =~ s/\/\/+/\//g;

        for my $met (@req_methods)
        {
            my $response = $http->request($met, $full_path, $options);
            my $status   = $response->{status};
            my $content  = $response->{content};
            my $length   = length($content) || 'null';
            my $url      = $response->{url};
            my $reason   = $response->{reason};

            if ($recursive && $status == 200 && $met eq 'GET' && $url =~ /\/$/)
            {
                lock($add_dir_lock);
                push @target_dirs, $full_path;
            }

            if ($filter)
            {
                my $match = 0;
                #filter format example: length>0 and status=200;status == 301
                #params: length, status, content, url
                for my $rule (split /;/, $filter)
                {
                    $rule =~ s/\bor\b/\|\|/;
                    $rule =~ s/\band\b/&&/;
                    $rule =~ s/$_/\$$_/g for qw(length status content url);
                    next if ($rule =~ /content/ && !$content);
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
                my $result = to_json({
                    status   => $status,
                    length   => $length,
                    reason   => $reason,
                    url      => $url,
                    method   => $met,
                });
                print $result . "\n";
            }
            else
            {
                print "[$status] URL: $url | method: $met | reason: $reason" .
                " | length: $length\n";
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
    -r, --recursive         Go recursive into directories (default)
    -w, --wordlist          The wordlist of paths to request
    -H, --headers           Define a header to be sent
    -p, --payload           Send some custom data to the server
    -f, --filter            Only display results matching with a filter
                            (See FILTERS below)
    --norecursive           Do not follow directories recursively

    Examples:
        ./fuzzer.pl -w wordlist.txt -T 16 http://example.com
        ./fuzzer.pl -w wordlist.txt -d 2 -u "Googlebot/1.0" https://example.com
        ./fuzzer.pl -w wordlist.txt -f 'content=~/admin/i' https://example.com

FILTERS:

        A filter is a collection of semicolon-separated expressions that are
    tested against the result of each request. When used, only the requests 
    matching with at least one the filters will be displayed. The filters can 
    contain basic comparissions and even Perl regular expressions. Any number of
    expressions can be combined using the logic operators 'or' and 'and' to form
    a filter and multiple filters can be joined into one by using a semicolon.
        Filters can be used to validate the following fields of a response:
        
        status  - the status code of the response (200, 301, 404, etc.)
        content - the content returned as response by the server
        length  - the binary length of the content (can have the value 'null')
        url     - the url that provided the response

    Examples of filters:
        'url =~ /.txt\$/ and status != 200'
        'status == 200; content =~ /admin/i'
        'status > 300 and status < 400 or status == 200'

HELP
    exit 0;
}

sub main
{
    my ($timeout, $tasks, $json, $delay) = (10, 10, undef, 0);
    my ($useragent, $filter, $payload) = ("fuzzer.pl/0.1", "", "");
    my $methods = "GET,POST,PUT,DELETE,HEAD,TRACE,*";
    my %headers;
    my $wordlist;

    GetOptions(
        "h|help"        => \&help,
        "j|json"        => \$json,
        "t|tasks=i"     => \$tasks,
        "d|delay=i"     => \$delay,
        "v|version"     => \&version,
        "f|filter=s"    => \$filter,
        "p|payload=s"   => \$payload,
        "T|timeout=i"   => \$timeout,
        "m|methods=s"   => \$methods,
        "H|headers=s%"  => \%headers,
        "w|wordlist=s"  => \$wordlist,
        "r|recursive!"  => \$recursive,
        "u|useragent=s" => \$useragent,
    ) || help();

    
    my $target = shift @ARGV;
    die "[!] No target specified!" unless $target;
    die "[!] No wordlist specified!" unless $wordlist;
    push @target_dirs, $target;
    open my $list, "<$wordlist" || die "[!] Can't open $wordlist for reading";
    while (<$list>)
    {
        chomp;
        $wordlist_queue->enqueue($_);
    }

    $wordlist_queue->end();

    while (@target_dirs)
    {
        $target = shift @target_dirs;
        #threads are created asynchronously!
        async {
            foreach (0 .. $tasks - 1)
            {
                threads->create('fuzzer_loop', $_, $target, \%headers, $methods,
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
