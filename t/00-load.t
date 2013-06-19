#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'LWP::Authen::OAuth2' ) || print "Bail out!\n";
}

diag( "Testing LWP::Authen::OAuth2 $LWP::Authen::OAuth2::VERSION, Perl $], $^X" );
