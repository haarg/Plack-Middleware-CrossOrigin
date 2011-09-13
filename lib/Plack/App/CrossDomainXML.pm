use strict;
use warnings;
package Plack::App::CrossDomainXML;
# ABSTRACT: Serves a crossdomain.xml file to allow cross domain requests by Flash
use parent qw(Plack::Component);

use Plack::Util::Accessor qw(meta_policy allow_access_from);
# TODO
# allow-access-from-identity
# allow-http-request-headers-from

sub prepare_app {
    my $self = shift;

    my $file = <<'END_HEAD';
<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
END_HEAD
    if ($self->meta_policy) {
        $file .= "<site-control permitted-cross-domain-policies=\"@{[ $self->meta_policy ]}\" />\n";
    }
    if (my $allow_origins = $self->allow_access_from) {
        $allow_origins = [$allow_origins]
            if !ref $allow_origins;
        for my $allow ( @{ $allow_origins } ) {
            my $domain = $allow;
            my $secure;
            if (ref $allow) {
                $domain = $allow->{domain};
                $secure = $allow->{secure};
            }
            $file .= "<allow-access-from domain=\"$domain\"";
            if (defined $secure) {
                $secure = lc $secure eq 'false'     ? 'false'
                        : $secure                   ? 'true'
                                                    : 'false';
                $file .= " secure=\"$secure\"";
            }
            $file .= "/>\n";
        }
    }
    $file .= "</cross-domain-policy>\n";
    $self->{_file} = $file;
}

sub call {
    my $self = shift;
    my $env = shift;
    return [200, ['Content-Type' => 'text/x-cross-domain-policy'], [$self->{_file}]];
}

1;

=head1 SYNOPSIS

    use Plack::App::CrossDomainXML;

    # Allow any WebDAV or standard HTTP request from any location.
    builder {
        mount '/crossdomain.xml' => Plack::App::CrossDomainXML->new(allow_access_from => '*');
        mount '/' => $app;
    };

=head1 DESCRIPTION

Serves the F<crossdomain.xml> file used by Flash to allow cross
domain requests.  Generally meant to be used by
L<Plack::Middleware::CrossOrigin>.  Currently only supports a subset
of the cross domain policy file specification.

=head1 CONFIGURATION

=over 8

=item meta_policy

Specifies the meta policy for the current domain, allowing additional
F<crossdomain.xml> files to be used.

=item allow_access_from

A list of domains to allow access from.  Domains can be specified
either as strings, or hashes with the keys C<domain> and C<secure>
specified.

=head1 SEE ALSO

* L<Cross-domain policy file for Flash|http://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html>

=end

