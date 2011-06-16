use strict;
use warnings;
package Plack::Middleware::CrossOrigin;
# ABSTRACT: Adds headers to allow Cross-Origin Resource Sharing
use parent qw(Plack::Middleware);

use Plack::Util;
use Plack::Util::Accessor qw(
    origins
    headers
    methods
    max_age
    expose_headers
    credentials
);

my @simple_headers = qw(
    Accept
    Accept-Language
    Content-Language
    Last-Event-ID
);
my @simple_response_headers = (@simple_headers, qw(
    Cache-Control
    Content-Language
    Content-Type
    Expires
    Last-Modified
    Pragma
));

sub prepare_app {
    my ($self) = @_;

    $self->methods( [qw(
        CANCELUPLOAD
        CHECKIN
        CHECKOUT
        COPY
        DELETE
        GET
        GETLIB
        HEAD
        LOCK
        MKCOL
        MOVE
        OPTIONS
        POST
        PROPFIND
        PROPPATCH
        PUT
        REPORT
        UNCHECKOUT
        UNLOCK
        UPDATE
        VERSION-CONTROL
    )] )
        unless defined $self->methods;

    $self->headers( [qw(
        Cache-Control
        Depth
        If-Modified-Since
        User-Agent
        X-File-Name
        X-File-Size
        X-Requested-With
        X-Prototype-Version
    )])
        unless defined $self->headers;
}

sub _origins {
    my $self = shift;
    return ref $self->origins ? @{ $self->origins } : $self->origins || ();
}

sub _methods {
    my $self = shift;
    return ref $self->methods ? @{ $self->methods } : $self->methods || ();
}

sub _headers {
    my $self = shift;
    return ref $self->headers ? @{ $self->headers } : $self->headers || ();
}

sub _expose_headers {
    my $self = shift;
    return ref $self->expose_headers ? @{ $self->expose_headers } : $self->expose_headers || ();
}

sub call {
    my ($self, $env) = @_;
    if (my $origin = $env->{HTTP_ORIGIN}) {
        my @origins = split / /, $origin;
        my $request_method = $env->{HTTP_ACCESS_CONTROL_REQUEST_METHOD};
        my $request_headers = $env->{HTTP_ACCESS_CONTROL_REQUEST_HEADERS};
        my @request_headers = $request_headers ? (split /,\s*/, $request_headers) : ();

        my $preflight = $env->{REQUEST_METHOD} eq 'OPTIONS' && $request_method;

        my %allowed_origins = map { $_ => 1 } $self->_origins;
        my @allowed_methods = $self->_methods;
        my %allowed_methods = map { $_ => 1 } @allowed_methods;
        my @allowed_headers = $self->_headers;
        my %allowed_headers = map { lc $_ => 1 } @allowed_headers;
        my @expose_headers = $self->_expose_headers;
        my %expose_headers = map { $_ => 1 } @expose_headers;

        my @headers;

        if (! $allowed_origins{'*'} ) {
            for my $origin (@origins) {
                return _return_403()
                    unless $allowed_origins{$origin};
            }
        }

        if ($preflight) {
            unless ( $allowed_methods{'*'} || $allowed_methods{$request_method} ) {
                return _return_403();
            }
            if (! $allowed_headers{'*'} ) {
                for my $header (@request_headers) {
                    return _return_403()
                        unless $allowed_headers{lc $header};
                }
            }
        }
        if ($self->credentials) {
            push @headers, 'Access-Control-Allow-Credentials' => 'true';
        }
        elsif ($allowed_origins{'*'}) {
            $origin = '*';
        }
        push @headers, 'Access-Control-Allow-Origin' => $origin;

        my $res;
        if ($preflight) {
            if ($allowed_methods{'*'}) {
                @allowed_methods = $request_method;
            }
            if ( $allowed_headers{'*'} ) {
                @allowed_headers = @request_headers;
            }

            if (defined $self->max_age) {
                push @headers, 'Access-Control-Max-Age' => $self->max_age;
            }
            push @headers, 'Access-Control-Allow-Methods' => $_
                for @allowed_methods;
            push @headers, 'Access-Control-Allow-Headers' => $_
                for @allowed_headers;

            $res = [200, [ 'Content-Type' => 'text/plain' ], [] ];
        }
        else {
            $res = $self->app->($env);
        }

        return $self->response_cb($res, sub {
            my $res = shift;

            if ($expose_headers{'*'}) {
                my %headers = @{ $res->[1] };
                delete @headers{@simple_response_headers};
                @expose_headers = keys %headers;
            }

            push @headers, 'Access-Control-Expose-Headers' => $_
                for @expose_headers;

            push @{$res->[1]}, @headers;
        });
    }
    # for preflighted GET requests, some WebKit versions don't include Origin
    # with the actual request.  Fixed in WebKit trunk and Chrome.  Current
    # releases of Safari still suffer from the issue.
    # https://bugs.webkit.org/show_bug.cgi?id=50773
    # http://code.google.com/p/chromium/issues/detail?id=57836
    elsif ($env->{REQUEST_METHOD} eq 'GET'
        && $env->{HTTP_USER_AGENT}
        && $env->{HTTP_USER_AGENT} =~ m{\bAppleWebKit/(\d+\.\d+)}
        && $1 < 534.19) {
        my $origin_header;
        # transforming the referrer into the origin is the best we can do
        my ( $origin ) = ( $env->{HTTP_REFERER} =~ m{\A ( \w+://[^/]+ )}msx );
        my %allowed_origins = map { $_ => 1 } $self->_origins;
        if ( $allowed_origins{'*'} ) {
            $origin_header = '*';
        }
        elsif ($origin && $allowed_origins{$origin} ) {
            $origin_header = $origin;
        }
        if ($origin_header) {
            return $self->response_cb($self->app->($env), sub {
                my $res = shift;
                push @{$res->[1]}, 'Access-Control-Allow-Origin' => $origin_header;
            });
        }
    }
    return $self->app->($env);
}

sub _return_403 {
    my $self = shift;
    return [403, ['Content-Type' => 'text/plain', 'Content-Length' => 9], ['forbidden']];
}

1;

=head1 SYNOPSIS

    # Allow any WebDAV or standard HTTP request from any location.
    builder {
        enable 'CrossOrigin', origins => '*';
        $app;
    };
    
    # Allow GET and POST requests from any location, cache results for 30 days.
    builder {
        enable 'CrossOrigin',
            origins => '*', methods => ['GET', 'POST'], max_age => 60*60*24*30;
        $app;
    };

=head1 DESCRIPTION

Adds Cross Origin Request Sharing headers used by modern browsers
to allow C<XMLHttpRequest> to work across domains.  This module
will also help protect against CSRF attacks in some browsers.

This module attempts to fully conform to the CORS spec, while
allowing additional flexibility in the values specified for the of
the headers.

=head1 CORS REQUESTS IN BRIEF

There are two types of CORS requests.  Simple requests, and preflighted
requests.

=head2 Simple Requests

A simple request is one that could be generated by a standard HTML
form.  Either a C<GET> or C<POST> request, with no additional
headers.  For these requests, the server processes the request as
normal, and attaches the correct CORS headers in the response.  The
browser then decides based on those headers whether to allow the
client script access to the response.

=head2 Preflighted Requests

If additional headers are specified, or a method other than C<GET>
or C<POST> is used, the request must be preflighted.  This means
that the browser will first send a special request to the server
to check if access is allowed.  If the server allows it by responding
with the correct headers, the actual request is then performed.

=head1 CSRF Protection

Some browsers will also provide same headers with cross domain
C<POST> requests from HTML forms.  These requests will also be
checked against the allowed origins and rejected before they reach
the rest of your Plack application.

=head1 CONFIGURATION

=over 8

=item origins

A list of allowed origins.  Origins should be formatted as a URL
scheme and host, with no path information. (C<http://www.example.com>)
'C<*>' can be specified to allow access from any location.  Must be
specified for this middleware to have any effect.  This will be
matched against the C<Origin> request header, and will control the
C<Access-Control-Allow-Origin> response header.  If the origin does
not match, the request is aborted.

=item headers

A list of allowed request headers.  'C<*>' can be specified to allow
any headers.  Controls the C<Access-Control-Allow-Headers> response
header.  Includes a set of headers by default to simplify working
with WebDAV and AJAX frameworks:

=for :list
* C<Cache-Control>
* C<Depth>
* C<If-Modified-Since>
* C<User-Agent>
* C<X-File-Name>
* C<X-File-Size>
* C<X-Prototype-Version>
* C<X-Requested-With>

=item methods

A list of allowed methods.  '*' can be specified to allow any
methods.  Controls the C<Access-Control-Allow-Methods> response
header.  Defaults to all of the standard HTTP and WebDAV methods.

=item max_age

The max length in seconds to cache the response data for.  Controls
the C<Access-Control-Max-Age> response header.  If not specified,
the web browser will decide how long to use.

=item expose_headers

A list of allowed headers to expose to the client. '*' can be
specified to allow the browser to see all of the response headers.
Controls the C<Access-Control-Expose-Headers> response header.

=item credentials

Whether the resource will be allowed with user credentials (cookies,
HTTP authentication, and client-side SSL certificates) supplied.
Controls the C<Access-Control-Allow-Credentials> response header.

=back

=head1 BROWSER SUPPORT

Different browsers have different levels of support for CORS headers.

=over 8

=item Gecko (Firefox, Seamonkey)

Initially supported in Gecko 1.9.1 (Firefox 3.5).  Supports the
complete CORS spec for C<XMLHttpRequest>s.

Does not yet provide the C<Origin> header for CSRF protection
(L<Bugzilla #446344|https://bugzilla.mozilla.org/show_bug.cgi?id=446344>).

=item WebKit (Safari, Google Chrome)

Initially supported in Safari 4 and Chrome 3.  The C<expose_headers>
feature is currently unsupported (L<WebKit bug #41210|https://bugs.webkit.org/show_bug.cgi?id=41210>).
The current release of Safari has a bug in its handling of preflighted
C<GET> requests (L<WebKit bug #50773|https://bugs.webkit.org/show_bug.cgi?id=50773>)
which has been fixed in WebKit v534.19 and Chrome 11.  This module uses the
C<Referer> header to work around the issue when possible.

Also provides the C<Origin> header for CSRF protection starting
with WebKit v528.5 (Chrome 2, Safari 4).

=item Internet Explorer

Initially supported in IE8.  Not supported with the standard
C<XMLHttpRequest> object.  A separate object, C<XDomainRequest>,
must be used.  Only C<GET> and C<POST> methods are allowed.  No
extra headers can be added to the request.  Neither the status code
or any headers aside from C<Content-Type> can be retrieved from the
response.

=item Opera

Not supported in any version of Opera.

=back

=head1 SEE ALSO

=head2 CORS Resources

=for :list
* L<W3C Spec for Cross-Origin Resource Sharing|http://www.w3.org/TR/cors/>
* L<Mozilla Developer Center - HTTP Access Control|https://developer.mozilla.org/En/HTTP_access_control>
* L<Mozilla Developer Center - Server-Side Access Control|https://developer.mozilla.org/En/Server-Side_Access_Control>
* L<Cross browser examples of using CORS requests|http://www.nczonline.net/blog/2010/05/25/cross-domain-ajax-with-cross-origin-resource-sharing/>
* L<MSDN - XDomainRequest Object|http://msdn.microsoft.com/en-us/library/cc288060%28v=vs.85%29.aspx>
* L<XDomainRequest - Restrictions, Limitations and Workarounds|http://blogs.msdn.com/b/ieinternals/archive/2010/05/13/xdomainrequest-restrictions-limitations-and-workarounds.aspx>
* L<Wikipedia - Cross-Origin Resource Sharing|http://en.wikipedia.org/wiki/Cross-Origin_Resource_Sharing>
* L<CORS advocacy|http://enable-cors.org/>

=head2 CSRF Resources

* L<Wikipedia - Cross-site request forgery|http://en.wikipedia.org/wiki/Cross-site_request_forgery>
* L<Stanford Web Security Research - Cross-Site Request Forgery|http://seclab.stanford.edu/websec/csrf/>
* L<WebKit Bugzilla - Add origin header to POST requests|https://bugs.webkit.org/show_bug.cgi?id=20792>
* L<Mozilla Bugzilla - Implement Origin header CSRF mitigation |https://bugzilla.mozilla.org/show_bug.cgi?id=446344>

=head2 Related Technologies

=for :list
* L<Cross-domain policy file for Flash|http://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html>
* L<Wikipedia - JSONP|http://en.wikipedia.org/wiki/JSONP>

=cut

