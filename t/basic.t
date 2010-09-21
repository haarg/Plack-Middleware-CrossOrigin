use strict;
use warnings;
use Test::More;

use Plack::Middleware::CrossOrigin;
use Plack::Test;
use Plack::Builder;

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => '*', methods => ['GET', 'POST'], max_age => 60*60*24*30, headers => '*';
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
            'Origin' => 'www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), '*', 'Access-Control-Allow-Origin header added';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Origin' => 'www.example.com',
        ]);
        $res = $cb->($req);
        is $res->header('Access-Control-Allow-Origin'), '*', 'Access-Control-Allow-Origin header added';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'X-Extra-Header',
            'Origin' => 'www.example.com',
        ]);
        $res = $cb->($req);
        ok $res->header('Access-Control-Allow-Origin'), 'Request with extra headers allowed';
    };

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => '*', methods => ['GET', 'POST'], max_age => 60*60*24*30, headers => 'X-Extra-Header';
        sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ 'Hello World' ] ] };
    },
    client => sub {
        my $cb = shift;
        my $req;
        my $res;

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'X-Extra-Header',
            'Origin' => 'www.example.com',
        ]);
        $res = $cb->($req);
        ok $res->header('Access-Control-Allow-Origin'), 'Request with explicitly listed extra header allowed';

        $req = HTTP::Request->new(OPTIONS => 'http://localhost/', [
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'X-Extra-Header-Other',
            'Origin' => 'www.example.com',
        ]);
        $res = $cb->($req);
        ok !$res->header('Access-Control-Allow-Origin'), 'Request with unmatched extra header rejected';
    };


done_testing;
