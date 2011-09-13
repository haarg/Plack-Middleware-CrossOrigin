use strict;
use warnings;
use Test::More 0.88;

use Plack::Middleware::CrossOrigin;
use Plack::App::CrossDomainXML;
use Plack::Test;
use Plack::Builder;

test_psgi
    app => builder {
        mount '/crossdomain.xml' => Plack::App::CrossDomainXML->new(allow_access_from => 'http://www.example.com');
        mount '/' => sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ 'Hello World' ] ] };
    },
    client => sub {
        my $cb = shift;
        my $req;
        my $res;

        $req = HTTP::Request->new(GET => 'http://localhost/crossdomain.xml');
        $res = $cb->($req);
        is $res->decoded_content, <<'END_XML', 'App returns correct document';
<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<allow-access-from domain="http://www.example.com"/>
</cross-domain-policy>
END_XML
        is $res->content_type, 'text/x-cross-domain-policy', '... with correct content type';
    };

test_psgi
    app => builder {
        enable 'CrossOrigin',
            origins => [ 'http://www.example.com' ],
            flash => 1,
        ;
        sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ 'Hello World' ] ] };
    },
    client => sub {
        my $cb = shift;
        my $req;
        my $res;

        $req = HTTP::Request->new(GET => 'http://localhost/crossdomain.xml');
        $res = $cb->($req);
        is $res->decoded_content, <<'END_XML', 'middleware option serves policy file on correct URL';
<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<allow-access-from domain="http://www.example.com"/>
</cross-domain-policy>
END_XML

        $req = HTTP::Request->new(GET => 'http://localhost/');
        $res = $cb->($req);
        is $res->decoded_content, 'Hello World', 'other URLs pass through as normal';
    };

done_testing;
