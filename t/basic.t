use strict;
use warnings;
use Test::More;

use Plack::Middleware::CrossOrigin;
use Plack::Test;
use Plack::Builder;

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => '*',
            headers => '*',
            methods => '*',
            max_age => 60*60*24*30,
            expose_headers => 'X-Exposed-Header',
        ;
        sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ 'Hello World' ] ] };
    },
    client => sub {
        my $cb = shift;
        my $req;
        my $res;

        $req = HTTP::Request->new(GET => 'http://localhost/');
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), undef, 'No extra headers added with no Origin header';

        $req = HTTP::Request->new(GET => 'http://localhost/', [
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), '*', 'Access-Control-Allow-Origin header added';
        is $res->header('Access-Control-Expose-Headers'), 'X-Exposed-Header', 'Access-Control-Expose-Headers header added';
        is $res->header('Access-Control-Max-Age'), undef, 'No Max-Age header for simple request';
        is $res->content, 'Hello World', "CORS handling doesn't interfere with request content";

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), '*', 'Access-Control-Allow-Origin header added for preflight';
        is $res->header('Access-Control-Allow-Methods'), 'POST', 'Access-Control-Allow-Methods header added for preflight';
        is $res->header('Access-Control-Max-Age'), 60*60*24*30, 'Max-Age header added for preflight';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'X-Extra-Header',
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        ok $res->header('Access-Control-Allow-Origin'), 'Request with extra headers allowed';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), undef, 'Preflight without method specified rejected';
    };

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => [ 'http://www.example.com' ],
            methods => ['GET', 'POST'],
            headers => ['X-Extra-Header', 'X-Extra-Header-2'],
            max_age => 60*60*24*30,
        ;
        sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ 'Hello World' ] ] };
    },
    client => sub {
        my $cb = shift;
        my $req;
        my $res;

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'X-Extra-Header',
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        ok $res->header('Access-Control-Allow-Origin'), 'Request with explicitly listed extra header allowed';
        is $res->header('Access-Control-Allow-Origin'), 'http://www.example.com', 'Explicitly listed origin returned';
        is $res->header('Access-Control-Allow-Headers'), 'X-Extra-Header, X-Extra-Header-2', 'Allowed headers returned';
        is $res->header('Access-Control-Allow-Methods'), 'GET, POST', 'Allowed methods returned';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'X-Extra-Header-Other',
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), undef, 'Request with unmatched extra header rejected';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Origin' => 'http://www.example2.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), undef, 'Request with unmatched origin rejected';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'DELETE',
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), undef, 'Request with unmatched method rejected';
    };

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => '*',
            methods => '*',
            credentials => 1,
        ;
        sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ 'Hello World' ] ] };
    },
    client => sub {
        my $cb = shift;
        my $req;
        my $res;

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Origin' => 'http://www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Credentials'), 'true', 'Resource with credentials adds correct header';
        is $res->header('Access-Control-Allow-Origin'), 'http://www.example.com', '... and an explicit origin';
    };

done_testing;
