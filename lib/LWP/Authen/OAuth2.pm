package LWP::Authen::OAuth2;

use 5.006;
use strict;
use warnings FATAL => 'all';

=head1 NAME

LWP::Authen::OAuth2 - Make requests to OAuth2 APIs.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

OAuth 2 is a protocol that let's a I<user> tell a I<service provider> that a
I<consumer> has permission to use the I<service provider>'s APIs to do things
that require access to the I<user>'s account.  For a full explanation of the
protocol, the terminology, and this module's role in the process, see
L<LWP::Authen::OAuth2::Overview>.

L<LWP::Authen::OAuth2> is a subclass of L<LWP::UserAgent> providing
convenience methods to help the consumer go through the initial permission
handshake, and after that to send signed requests to the service provider's
API, including automatic retry logic when access tokens expire.

This module will not work with OAuth 1.  For a module to help with that, see
the similarly named but otherwise unrelated L<LWP::Authen::OAuth>.

In the interest of focusing on one task, it is as important to know what this
module does not do as it is to know what it does.  This module does none of
the following necessary tasks for using OAuth 2: set up your client
relationship with the service provider, script any of the necessary user
interactions for the intial handshake, or provide any assistance with how
you store private information beyond serializing/deserializing tokens to a
string.

    use LWP::Authen::OAuth2;

    # Constructor for the first time through.
    my $oauth2 = LWP::Authen::OAuth2->new(
                     client_id => "Public from service provider",
                     client_secret => "s3cr3t fr0m svc prov",
                     service_provider => "Google",
                     request_url => "https://your.url.com/",
                     # Optional hook, but recommended.
                     on_refresh => \&store_tokens,
                 );

    # URL for user to visit to start the process.
    my $url = $oauth2->authorization_url();

    # Get your tokens from the service provider.
    $oauth2->request_tokens(code => $code);

    # Access the API.  Consult the service_provider's documentation for when
    # to do which.
    $oauth2->get($url, %values);
    $oauth2->post($url, %values);
    $oauth2->put($url, %values);

    # Refresh your access token - if possible done for you automatically
    # under the hood.
    $oauth2->refresh_access_token();

    # Get your token as a string you can easily store, pass around, etc.
    my $token_string = $oauth2->tokens->serialize;

    # Constructor for the second time through if you have tokens.  Whether
    # this works depends on the service provider, and you won't know for
    # sure until you try their API.
    my $oauth2 = LWP::Authen::OAuth2->new(
                     client_id => "Public from service provider",
                     client_secret => "s3cr3t fr0m svc prov",
                     service_provider => "Google",
                     request_url => "https://your.url.com/",
                     tokens => $token_string,
                     # Optional hook, but recommended.
                     on_refresh => \&store_tokens,
                 );

=head1 AUTHOR

Ben Tilly, C<< <btilly at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-lwp-authen-oauth2 at rt.cpan.org>, or through
the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=LWP-Authen-OAuth2>.  I will
be notified, and then you'll automatically be notified of progress on your
bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc LWP::Authen::OAuth2


You can also look for information at:

=over 4

=item * Github (submit patches here)

L<https://github.com/btilly/perl-oauth2>

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=LWP-Authen-OAuth2>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/LWP-Authen-OAuth2>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/LWP-Authen-OAuth2>

=item * Search CPAN

L<http://search.cpan.org/dist/LWP-Authen-OAuth2/>

=back


=head1 ACKNOWLEDGEMENTS

Thanks to L<Rent.com|http://www.rent.com> for their generous support in
letting me develop and release this module.  My thanks also to Nick
Wellnhofer <wellnhofer@aevum.de> for Net::Google::Analytics::OAuth2 which
was very enlightening while I was trying to figure out the details of how to
connect to Google with OAuth2.

=head1 LICENSE AND COPYRIGHT

Copyright 2013 Rent.com.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of LWP::Authen::OAuth2
