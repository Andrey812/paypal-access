# perl

use Paypal_openid;
use Data::Dumper;

use strict;
use warnings;

my $ppa = Paypal_openid->new({
	'client_id'     => 'your_client_id',							# Mandatory
	'client_secret'	=> 'your_secret_key',							# Mandatory
        'redirect_url'  => 'https://test.com/cgi-bin/ppauth',					# Mandatory
	'scope'		=> 'openid',								# Optional
});

# $ppa->get_auth_url for generation redirect url here

print "Get access token\n";
print Data::Dumper::Dumper($ppa->get_access_token('very_long_access_code_received_from_paypal'));
print Data::Dumper::Dumper($ppa->get_error);

print "Refresh access token\n";
print Data::Dumper::Dumper($ppa->refresh_access_token);
print Data::Dumper::Dumper($ppa->get_error);

print "Validate access token\n";
print Data::Dumper::Dumper($ppa->validate_access_token);
print Data::Dumper::Dumper($ppa->get_error);

print "Get PayPal user profile info\n";
print Data::Dumper::Dumper($ppa->get_profile);
print Data::Dumper::Dumper($ppa->get_error);

print "Close PayPal user session\n";
print Data::Dumper::Dumper($ppa->close_session);
print Data::Dumper::Dumper($ppa->get_error);

print "\n";

exit 0;
