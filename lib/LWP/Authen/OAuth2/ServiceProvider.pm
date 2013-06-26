package LWP::Authen::OAuth2::ServiceProvider;

use 5.006;
use strict;
use warnings FATAL => 'all';
use Carp qw(croak);
use Memoize qw(memoize);
use Module::Load qw(load);

our @CARP_NOT = qw(LWP::Authen::OAuth2::Args);

use LWP::Authen::OAuth2::Args qw(copy_option assert_options_empty);

# Construct a new object.
sub new {
    my $class = shift;
    my $opt = {@_};

    # I start as an empty hashref.
    my $self = {};

    # But what class am I supposed to actually be?
    if (not exists $opt->{service_provider}) {
        bless $self, $class;
    }
    else {
        # Convert "Google" to "LWP::Authen::OAuth2::ServiceProvider::Google"
        $class = service_provider_class(delete $opt->{service_provider});
        my $flow = delete $opt->{flow};
        if (not defined($flow)) {
            $flow = "default";
        }
        bless $self, $class->flow_class($flow);
    }

    # Now let us consume options.  2 args = required, 3 = defaulted.

    # These are required, NOT provided by this class, but are by subclasses.
    for my $field (qw(token_endpoint authorization_endpoint)) {
        if ($self->can($field)) {
            $self->copy_option($opt, $field, $self->$field);
        }
        else {
            $self->copy_option($opt, $field);
        }
    }

    # These are defaulted by this class, maybe overridden by subclasses.
    for my $action (qw(authorization request refresh)) {
        my $field = "$action\_required_params";
        $self->copy_option($opt, $field, [$self->$field]);

        $field = "$action\_more_params";
        $self->copy_option($opt, $field, [$self->$field]);

        $field = "$action\_default_params";
        $self->copy_option($opt, $field, {$self->$field});
    }

    $self->assert_options_empty($opt);
    return $self;
}

sub collect_action_params {
    my $self = shift;
    my $action = shift;
    my $oauth2 = shift;
    my $opt = {@_};

    my $default = $self->{"$action\_default_params"};

    if ($oauth2->is_strict) {
        # We copy one by one with testing.
        my $result = {};
        for my $param (@{ $self->{"$action\_required_params"}}) {
             if (exists $opt->{$param}) {
                 if (defined $opt->{$param}) {
                     $result->{$param} = delete $opt->{$param};
                 }
                 else {
                     croak("Cannot pass undef for required param '$param'");
                 }
             }
             elsif (defined $oauth2->{$param}) {
                 $result->{$param} = $oauth2->{$param};
             }
             elsif (defined $default->{$param}) {
                 $result->{$param} = $default->{$param};
             }
             else {
                 croak("Missing required param '$param'");
             }
        }

        for my $param (@{ $self->{"$action\_more_params"} }) {
            for my $source ($result, $opt, $oauth2, $default) {
                if (exists $source->{$param}) {
                    # Only add it if it is not undef.  Else hide.
                    if (defined $source->{$param}) {
                        $result->{$param} = $source->{$param};
                    }

                    # For opt only, delete if it was found.
                    if ($opt == $source) {
                        delete $opt->{$param};
                    }

                    last; # source
                    # (undef is deliberate override, which is OK)
                }
            }
        }

        $self->assert_options_empty($opt);

        # End of strict section.
        return $result;
    }
    else {
        # Not strict  just bulk copy.
        my $result = {
            %$default,
            (
                map $oauth2->{$_},
                    @{ $self->{"$action\_required_params"} },
                    @{ $self->{"$action\_more_params"} }
            ),
            %$opt
        };
        for my $key (keys %$result) {
            if (not defined($result->{$key})) {
                delete $result->{$key};
            }
        }
        return $result;
    }
}

# Override for your flows if you have multiple.
sub flow_class {
    my ($class, $name) = @_;
    if ("default" eq $name) {
        return $class;
    }
    else {
        croak("Flow '$name' not defined for '$class'");
    }
}

memoize("service_provider_class");
sub service_provider_class {
    my $short_name = shift;
    eval {
        load("LWP::Authen::OAuth2::ServiceProvider::$short_name");
    };
    if ($@) {
        eval {
            load($short_name);
        };
        if ($@) {
            croak("Service provider '$short_name' not found");
        }
        else {
            return $short_name;
        }
    }
    else {
        return "LWP::Authen::OAuth2::ServiceProvider::$short_name";
    }
}

# DEFAULTS (should be overridden)
sub authorization_required_params {
    return qw(response_type client_id);
}

sub authorization_more_params {
    return qw(redirect_uri state scope);
}

sub authorization_default_params {
    return qw(response_type code);
}

sub request_required_params {
    return qw(grant_type client_id client_secret code);
}

sub request_more_params {
    return qw(state);
}

sub request_default_params {
    return qw(grant_type authorization_code);
}

sub refresh_required_params {
    return qw(grant_type refresh_token client_id client_secret code);
}

sub refresh_more_params {
    return ();
}

sub refresh_default_params {
    return qw(grant_type refresh_token);
}

=head1 NAME

LWP::Authen::OAuth2::ServiceProvider - Understand OAuth2 Service Providers

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

This is a base module for representing an OAuth 2 service provider.  It is
implicitly constructed from the parameters to C<LWP::Authen::OAuth2->new>,
and is automatically delegated to when needed.

The first way to try to specify the service provider is with the parameters
C<service_provider> and possibly C<flow>:

    LWP::Authen::OAuth2->new(
        ...
        service_provider => "Foo",
        flow => "Bar", # optional
        ...
    );

The first parameter will cause L<LWP::Authen::OAuth2::ServiceProvider> to
look for either C<LWP::Authen::OAuth2::ServiceProvider::Foo>, or if that is
not found, for C<Foo>.  (If neither is present, an exception will be thrown.)
The second parameter will be passed to that module which can choose to
customize the service provider behavior based on the flow.

The other way to specify the service provider is by passing in sufficient
parameters to create a custom one on the fly:

    LWP::Authen::OAuth2->new(
        ...
        authorization_endpoint => $authorization_endpoint,
        token_endpoint => $token_endpoint,

        # These are optional but let you get the typo checks of strict mode
        authorization_required_params => [...],
        authorization_more_params => [...],
        ...
    );

See L<LWP::Authen::OAuth2::Overview> if you are uncertain how to figure out
the I<Authorization Endpoint> and I<Token Endpoint> from the service
provider's documentation.

=head1 KNOWN SERVICE PROVIDERS

The following service providers are provided in this distribution, hopefully
with useful defaults:

=over 4

=item * L<LWP::Authen::OAuth2::ServiceProvider::Google|Google>

=back

=head1 SUBCLASSING

A minimal subclass for a given service provider should override the methods
C<authorization_endpoint> and C<token_endpoint>.  For the benefit of people
who choose to get the error checks of strict mode, please override
C<authorization_required_params> and C<authorization_more_params> as well if
the service provider requires or allows more than the default.  There is no
harm in parameters being duplicated between these lists should your service
provider require a parameter that is optional in the specification.

Many service providers accept different parameters for different flows.  To
accommodate that, a more complete subclass should have a subsubclass for each
flow, and then override C<flow_class> to map the flow argument to the
appropriate child class for that flow.  The flow C<default> should be
supported and be sent to whatever flow most closely resembles
I<webserver application> as that is the most likely flow for a Perl client to
use.

To accommodate the fact that so much of the specification can be specific to
the service provider, most calls to C<LWP::Authen::OAuth2> are delegated to
the service provider, and you are free to override any that you need to.
Though hopefully you won't need to.

=head1 CONTRIBUTING

Patches contributing service provider subclasses to this distributions are
encouraged.  Please make sure that you have done the following.

=over 4

=item * Implement it reasonably completely

The more completely implemented, the better.

=item * Name it properly

The name should be of the form:

    LWP::Authen::OAuth2::ServiceProvider::$ServiceProvider

=item * List it

It needs to be listed as a known service provider in this module.

=item * Test it

It is impossible to usefully test a service provider module without client
secrets.  However you can have public tests that it compiles, and private
tests that will, if someone supplies the necessary secrets, run fuller tests
that all works.  See the existing unit tests for examples.

=item * Include it

Your files need to be included in the C<MANIFEST> in the root directory.

=item * Document registration

A developer should be able to read your module and know how to register
themselves as a client of the service provider.

=item * List Useful Flows

Please list the flows that the service provider uses, with just enough
detail that a developer can figure out which one to use.

=item * Document important quirks

If the service provider requires or allows useful parameters, try to mention
them.

=item * Document limitations

If there are limitations in your implementation, please state them.

=item * Link to official documentation

If the service provider provides official OAuth 2 documentation, please link
to it.  Ideally a developer will not need to refer to it, but should know how
to find it.

=back

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

    perldoc LWP::Authen::OAuth2::ServiceProvider

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

1
