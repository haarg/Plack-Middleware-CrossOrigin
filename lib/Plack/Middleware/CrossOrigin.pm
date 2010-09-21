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

sub call {
    my ($self, $env) = @_;

    if ($env->{HTTP_ORIGIN}) {
        my @headers = $self->cors_headers($env);

        my $res;
        if ($env->{REQUEST_METHOD} eq 'OPTIONS') {
            $res = [200, [ 'Content-Type' => 'text/plain' ], [] ];
        }
        else {
            $res = $self->app->($env);
        }
        return $self->response_cb($res, sub {
            my $res = shift;
            push @{$res->[1]}, @headers;
        });
    }
    return $self->app->($env);
}

sub cors_headers {
    my $self = shift;
    my $env = shift;
    my $preflight = $env->{REQUEST_METHOD} eq 'OPTIONS';
    my @headers;

    my @allowed_origins = ref $self->origins ? @{ $self->origins } : $self->origins || ();
    my %allowed_origins = map { $_ => 1 } @allowed_origins;
    my @allowed_methods = ref $self->methods ? @{ $self->methods } : $self->methods || ();
    my %allowed_methods = map { $_ => 1 } @allowed_methods;
    my @allowed_headers = ref $self->headers ? @{ $self->headers } : $self->headers || ();
    my %allowed_headers = map { lc $_ => 1 } @allowed_headers;

    my $request_method = $env->{HTTP_ACCESS_CONTROL_REQUEST_METHOD};
    my $request_headers = $env->{HTTP_ACCESS_CONTROL_REQUEST_HEADERS};
    my @request_headers = $request_headers ? (split /,\s*/, $request_headers) : ();

    my @origins = split / /, $env->{HTTP_ORIGIN};
    return
        unless @origins;

    if (! $allowed_origins{'*'} ) {
        for my $origin (@origins) {
            return
                unless $allowed_origins{$origin};
        }
    }
    if ($preflight) {
        return
            if ! $request_method;
        unless ( $allowed_methods{'*'} || $allowed_methods{$request_method} ) {
            return;
        }
        if (! $allowed_headers{'*'} ) {
            for my $header (@request_headers) {
                return
                    unless $allowed_headers{lc $header};
            }
        }
    }
    if ($self->credentials) {
        push @headers, 'Access-Control-Allow-Origin' => $env->{HTTP_ORIGIN};
        push @headers, 'Access-Control-Allow-Credentials' => 'true';
    }
    else {
        if ($allowed_origins{'*'}) {
            push @headers, 'Access-Control-Allow-Origin' => '*';
        }
        else {
            push @headers, 'Access-Control-Allow-Origin' => $env->{HTTP_ORIGIN};
        }
    }
    if ($preflight) {
        if ($self->max_age) {
            push @headers, 'Access-Control-Max-Age' => $self->max_age;
        }
        if ($allowed_methods{'*'}) {
            push @headers, 'Access-Control-Allow-Methods' => $request_method;
        }
        else {
            push @headers, 'Access-Control-Allow-Methods' => $_
                for @allowed_methods;
        }
        if ( $allowed_headers{'*'} ) {
            push @headers, 'Access-Control-Allow-Headers' => $_
                for @request_headers;
        }
        else {
            push @headers, 'Access-Control-Allow-Headers' => $_
                for @allowed_headers;
        }
    }
    if ($self->expose_headers) {
        my @expose_headers = ref $self->expose_headers ? @{ $self->expose_headers } : $self->expose_headers;
        push @headers, 'Access-Control-Allow-Origin' => $_
            for @expose_headers;
    }
    return @headers;
}

1;

=head1 SYNOPSIS

    builder {
        enable 'CrossOrigin',
            origins => '*', methods => ['GET', 'POST'], max_age => 60*60*24*30;
        $app;
    };

=head1 DESCRIPTION

Adds Cross Origin Request Sharing headers used by recent browsers
to allow XMLHttpRequests across domains.

=head1 CONFIGURATION

=over 8

=item origins

A list of allowed origins.  '*' can be specified to allow access from
any origin.

=item headers

A list of allowed headers.  '*' can be specified to allow any headers.

=item methods

A list of allowed methods.  '*' can be specified to allow any methods.

=item max_age

The max length in seconds to cache the response data for.

=item expose_headers

A list of allowed headers to expose to the client.

=item credentials

Whether the resource supports credentials.

=back

=method cors_headers ( $env )

Returns a list of headers to add for a CORS request given the request and the configuration.

=head1 SEE ALSO

=for :list
* L<W3C Spec for Cross-Origin Resource Sharing|http://www.w3.org/TR/cors/>
* L<Mozilla Developer Center - HTTP Access Control|https://developer.mozilla.org/En/HTTP_access_control>
* L<Mozilla Developer Center - Server-Side Access Control|https://developer.mozilla.org/En/Server-Side_Access_Control>

=cut

