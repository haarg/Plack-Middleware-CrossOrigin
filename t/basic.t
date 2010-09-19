use strict;
use warnings;
use Test::More;

use Plack::Middleware::CrossOrigin;
use Plack::Test;
use Plack::Builder;

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => '*', methods => ['GET', 'POST'], max_age => 60*60*24*30;
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
    };

done_testing;
