use strict;
use warnings;
use Plack::Builder;
use Plack::App::File;
use Plack::Request;
use Plack::Util;
use Plack::Middleware::CrossOrigin;
use Socket;

sub alt_addr {
    my $address = shift;
    if ($address =~ /^[\d.]+$/) {
        return gethostbyaddr(inet_aton($address), AF_INET);
    }
    else {
        return inet_ntoa(inet_aton($address));
    }
}

builder {
    enable sub {
        my $app = shift;
        sub {
            my $env = shift;
            if ($env->{'psgi.multithread'} || $env->{'psgi.multiprocess'}) {
                return [401, ['Content-Type' => 'text/plain'], ['Unsupported server.  Please use a single threaded, single process server.']];
            }
            $app->($env);
        };
    };
    my $co_mw = Plack::Middleware::CrossOrigin->new(
        origins => '*',
        methods => '*',
        expose_headers => '*',
        max_age => 0,
    );
    my $last_cors = '';
    mount '/last_cors' => sub {
        my $out = $last_cors;
        $last_cors = '';
        [200, ['Content-Type' => 'text/plain'], [$out]];
    };
    mount '/cors' => builder {
        my $main_app_run;
        enable sub {
            my $app = shift;
            sub {
                my $env = shift;
                my $req = Plack::Request->new($env);
                $main_app_run = undef;
                my $in_head = $req->headers;
                return Plack::Util::response_cb($app->($env), sub {
                    my $res = shift;
                    if ( $req->method eq 'OPTIONS' && $in_head->header('Access-Control-Request-Method') ) {
                        $last_cors .= "Preflight request:\n";
                    }
                    else {
                        $last_cors .= "Actual request:\n";
                    }
                    if ( $main_app_run ) {
                        $last_cors .= "  Main Plack app run\n";
                    }

                    $last_cors .= "  Incoming:\n";
                    $last_cors .= sprintf "    Method:    %s\n", $req->method;
                    if ( defined $in_head->header('Origin') ) {
                        $last_cors .= sprintf "    Origin:    %s\n", $in_head->header('Origin');
                    }
                    $in_head->scan( sub {
                        my ($k, $v) = @_;
                        return
                            unless $k =~ /^Access-Control/i;
                        $k =~ s/\b(\w)(\w+)\b/\u$1\L$2/g;
                        $last_cors .= sprintf "    %s:    %s\n", $k, $v;
                    } );
                    $last_cors .= "  Response:\n";
                    $last_cors .= sprintf "    Status code:    %s\n", $res->[0];

                    my %out_headers = @{ $res->[1] };
                    my @cors_headers = grep { /^Access-Control/i } keys %out_headers;
                    for my $header (@cors_headers) {
                        for my $value (Plack::Util::header_get($res->[1], $header)) {
                            $last_cors .= sprintf "    %-30s: %s\n", $header, $value;
                        }
                    }
                    if ( $req->method ne 'OPTIONS' || ! $in_head->header('Access-Control-Request-Method') ) {
                        $res->[2] = [$last_cors];
                        $last_cors = '';
                    }
                });
            };
        };
        enable sub { $co_mw->wrap($_[0]) };
        sub {
            $main_app_run = 1;
            [ 200, ['X-Some-Other-Header' => 1, 'Content-Type' => 'text/plain'], [ 'output' ] ]
        };
    };
    mount '/' => sub {
        my $env = shift;
        my $req = Plack::Request->new($env);
        my $cors = $req->base;
        $cors->host(alt_addr($cors->host));
        $cors->path($cors->path . 'cors');

        my $last_cors = $req->base;
        $last_cors->path($last_cors->path . 'last_cors');

        return [ 200, ['Content-Type' => 'text/html'], [ sprintf <<'END_HTML', $cors, $last_cors ] ];
<!DOCTYPE html>
<html>
<head>
    <title>CORS Test</title>
    <style type="text/css">
        textarea {
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div>
        <form id="cors-form">
            <div>Requesting from %s</div>
            <div>
                <label>Method
                    <select id="request-method">
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="OPTIONS">OPTIONS</option>
                        <option value="PUT">PUT</option>
                        <option value="MODIFY">MODIFY</option>
                    </select>
                </label>
            </div>
            <fieldset>
                <legend>Headers</legend>
                <label><input type="checkbox" id="x-requested-with" /> Add X-Requested-With</label>
                <label><input type="checkbox" id="x-something-else" /> Add X-Something-Else</label>
            </fieldset>
            <div><button>Send Request</button></div>
            <div>Result Status: <span id="result-status"></span></div>
            <div>Results: <div><textarea cols="100" rows="20" readonly="readonly" id="results"></textarea></div></div>
        </form>
    </div>
    <script type="text/javascript">
        (function(){
            var form = document.getElementById('cors-form');
            var results = document.getElementById('results');
            var status = document.getElementById('result-status');
            var method = document.getElementById('request-method');
            var xrequestedwith = document.getElementById('x-requested-with');
            var xsomethingelse = document.getElementById('x-something-else');

            results.value = '';

            form.addEventListener("submit", function(e) {
                e.preventDefault();
                results.value = '';
                status.innerHTML = 'Running';
                var xhr = new XMLHttpRequest();
                xhr.open(method.value, '%1$s', true);
                if (xrequestedwith.checked) {
                    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                }
                if (xsomethingelse.checked) {
                    xhr.setRequestHeader('X-Something-Else', 'something-else');
                }

                xhr.onreadystatechange = function() {
                    if (xhr.readyState == 4) {
                        if (xhr.status == 200) {
                            status.innerHTML = 'Success';
                            results.value = xhr.responseText;
                            if (xhr.getResponseHeader('X-Some-Other-Header')) {
                                results.value += "\nExtra header was exposed\n";
                            }
                        }
                        else {
                            status.innerHTML = 'Failure';
                            var xhr2 = new XMLHttpRequest();
                            xhr2.open('GET', '%2$s', true);
                            xhr2.onreadystatechange = function() {
                                if (xhr2.readyState == 4) {
                                    results.value = xhr2.responseText;
                                }
                            };
                            xhr2.send();
                        }
                    }
                };
                xhr.send();
            }, false);
        })();
    </script>
</body>
</html>
END_HTML
    };
};

