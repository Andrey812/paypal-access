package Paypal_openid;

use strict;
use warnings;

=head1 NAME

	Paypal_openid - Authentication layer for Paypal openid API

=head1 SYNOPSIS
	
	Paypal open id sign up process sequence:
	
	For first, you must have web application
	registered in PayPal, valid CLIENT_ID 
	and CLIENT_SECRET keys, received from PayPal.

	Your web application has url with cgi script
	which implements PayPal auth process.
	
		Create a paypal open id object using method new();
		my $ppa = Paypal_openid->new(
			{ 
				...
				see params in the new() method description
				...
			}
		);

	When user clicks to 'Sign up with PayPal' button, he should
	be redirected to url which was generated using get_auth_url
	method.

		my $redirect_url = $ppa->get_auth_url;	
	
	When user will be redirected back according defined url,
	your script should extract CGI param 'code'
	and get tokens using get_access_token() method
	
		$ppa->get_access_token($code_returned_from_paypal);

	If previous method returned true (in fact this method returns hash ref
	with access keys and some other values), you can take profile info of 
	user and use these values for sign up

		my $user_info = $ppa->get_profile;

	If one of methods returned undef, you can extract error using method
	get_error();

		my $err_string = $ppa->get_error;

	There are also optional methods for refresh and validate access tokens
	and for end PayPal session. You can read about them, about extended
	params and returned values for all methods in description of each method.

=cut

our $VERSION = 1.0;

use URI::Escape;
use JSON::XS;
use LWP::UserAgent;

local($HTTP::Headers::TRANSLATE_UNDERSCORE);
$HTTP::Headers::TRANSLATE_UNDERSCORE = undef;
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 1;

use constant AUTHORIZATION_ENDPOINT 
	=> 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize';

use constant ACCESS_TOKEN_ENDPOINT
	=> 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/tokenservice';

use constant VALIDATE_ENDPOINT
	=> 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/checkid';

use constant PROFILE_ENDPOINT
	=> 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/userinfo';

use constant LOGOUT_ENDPOINT
	=> 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/endsession';

=head2 Paypal_openid::new
	
	Paypal open id access object constructor.
	
	Usage: 
	
		my $ppa = Paypal_openid->new(
			{
			# key of paypal applicaton <MANDATORY>
			'client_id' 	=> 'CLIENT_ID',
			
			# secret string of paypal application <MANDATORY>
			'client_secret' => 'CLIENT_SECRET',

			# url login form of your website <MANDATORY>
			'redirect_url' 	=> 'REDIRECT_URL',
			
			# Data which should be returned from paypal profile [optional]
			# But when you change it, remember that param 'openid' is always mandatory
			'scope'		=> 'openid email',

			# Then endpoints below are hardcoded as constants 
			# in the module's code. But it is possible to set them.
			'authorization_endpoint' => 'https://',
			'access_token_endpoint' => 'https://',
			'profile_endpoint' => 'https://',
			'validate_endpoint' => 'https://',
			'logout_endpoint' => 'https://',
			}
		);

	Return:
		PayPal access object ($ppa)
=cut
sub new {
	my ($class, $params) = @_;

	my $self = {
		'authorization_endpoint'=> ( $params -> {'authorization_endpoint'} 
						|| AUTHORIZATION_ENDPOINT ),

		'access_token_endpoint' => ( $params -> {'access_token_endpoint'}
						|| ACCESS_TOKEN_ENDPOINT ),
		
		'profile_endpoint' 	=> ( $params -> {'profile_endpoint'}
						|| PROFILE_ENDPOINT ),
		
		'validate_endpoint' 	=> ( $params -> {'validate_endpoint'}
						|| VALIDATE_ENDPOINT ),
		
		'logout_endpoint' 	=> ( $params -> {'logout_endpoint'}
						|| LOGOUT_ENDPOINT ),

		'scope'			=> ( $params -> {'scope'} 
							? uri_escape($params->{'scope'})
							: uri_escape('openid profile email') ),

		'client_id'		=> $params -> { 'client_id' },
		'client_secret'		=> $params -> { 'client_secret' },
		'redirect_url'		=> uri_escape( $params->{'redirect_url'} ),

		'state'			=> time() . int(rand(999)),
		'error'			=> "",
	};
	
	bless $self, $class;

	return $self;
}

=head2	Paypal_openid::get_auth_url

	Make and return url for user, which should be used for paypal sign in
	and user should be redirected back to redirect_url for use the next
	method 'get_access_token'

	Usage:
	
		my $auth_url = $ppa->get_auth_url;

	Return:
		url for client pointed to Paypal Auth form
=cut
sub get_auth_url {
	my ( $self ) = @_;

	my $auth_url = $self -> {'authorization_endpoint'}
		. '?client_id=' 	. $self -> {'client_id'}
		. '&scope=' 		. $self -> {'scope'}
		. '&redirect_uri='	. $self -> {'redirect_url'}
		. '&state'		. $self -> {'state'}
		. '&nonce='		. time() . int(rand(999))
		. '&response_type=code';

	return $auth_url;
}

=head2	Paypal_openid::get_access_token

	Using given code from previous step try to get PayPal's access token

	Usage:

		my $token = $ppa->get_access_token($code);

	Params:
		<$code> - auth code from user's redirect of previous call
	
	Return:
		Hash ref with 3 possible tokens:
		- access_token - key for get profile info
		- id_token - key for validate access token
		- refresh token - key for refresh token when expired
		- token_type - string, name of token's type
		- expires_in - lifetime of access token in seconds
		- expire_timestamp - timestamp when token will be expired
		
		OR
		undef - if error
		Use get_error method for see error explanation
=cut
sub get_access_token {
	my ( $self, $code ) = @_;

	my ( $res_code, $res_data ) = _http_query(
		$self -> {'access_token_endpoint'},
		'post',
		{
			'client_id' 	=> $self -> {'client_id'},
			'client_secret'	=> $self -> {'client_secret'},
			'grant_type'	=> 'authorization_code',
			'code'		=> $code,
		}
	);

	if ( $res_code ) {
		my $data = decode_json($res_data);

		$self -> { $_ } = $data -> { $_ } 
			foreach qw/refresh_token access_token id_token token_type expires_in/;

		$data -> {'expire_timestamp'} = time() + $data -> {'expires_in'};

		return $data;
	}
	else {
		$self->{'error'} = "Query has returned error: " . $res_data;
		return undef;
	};
}

=head2	Paypal_openid::refresh_access_token

	Get new access token if it has been expired

	Usage:
		my $new_token = $ppa->refresh_access_token;
	
	Return:
		Hash ref with new access token data
		OR
		undef - if error
		Use get_error method for see error explanation
=cut
sub refresh_access_token {
	my ( $self ) = @_;

	my ( $res_code, $res_data ) = _http_query(
		$self -> {'access_token_endpoint'},
		'post',
		{
			'client_id' 	=> $self -> {'client_id'},
			'client_secret'	=> $self -> {'client_secret'},
			'grant_type' 	=> 'refresh_token',
			'refresh_token'	=> $self -> {'refresh_token'},
		}
	);

	if ( $res_code ) {
		my $data = decode_json($res_data);
		
		$self -> { $_ } = $data -> { $_ } 
			foreach qw/access_token token_type expires_in/;

		$data -> {'expire_timestamp'} = time() + $data -> {'expires_in'};

		return $data;
	}
	else {
		$self->{'error'} = "Query has returned error: " . $res_data;
		return undef;
	};
}

=head2	Paypal_openid::validate_access_token

	Check if exist access token is valid

	Usage:
		my $new_token = $ppa->validate_access_token;
	
	Return:
		Hash ref with info about session of user
		OR
		undef - if error
		Use get_error method for see error explanation
=cut
sub validate_access_token {
	my ( $self ) = @_;

	my ( $res_code, $res_data ) = _http_query(
		$self -> {'validate_endpoint'},
		'post',
		{
			'access_token'	=> $self -> {'id_token'},
		}
	);

	if ( $res_code ) {
		my $data = decode_json($res_data);
		return $data;
	}
	else {
		$self->{'error'} = "Query has returned error: " . $res_data;
		return undef;
	};
}

=head2	Paypal_openid::close_session

	Close PayPal session of user

	Usage:
		my $user_profile = $ppa->close_session;
	
	Return:
		undef - if error
		Use get_error method for see error explanation
=cut
sub close_session {
	my ( $self ) = @_;

	my ( $res_code, $res_data ) = _http_query(
		$self -> {'logout_endpoint'},
		'get',
		{
			'redirect_url' 	=> $self -> {'redirect_url'},
			'id_token'	=> $self -> {'id_token'},
			'state'		=> $self -> {'state'},
			'logout'	=> 'true',
		}
	);

	if ( $res_code ) {
		return $res_data;
	}
	else {
		$self->{'error'} = "Query has returned error: " . $res_data;
		return undef;
	};
}



=head2	Paypal_openid::get_profile

	Get info about PayPal user profile

	Usage:
		my $user_profile = $ppa->get_profile;
	
	Return:
		Hash ref with user profile data (depending from scope)
		OR
		undef - if error
		Use get_error method for see error explanation
=cut
sub get_profile {
	my ( $self ) = @_;

	my ( $res_code, $res_data ) = _http_query(
		$self -> {'profile_endpoint'},
		'post',
		{
			'schema' 	=> 'openid',
			'access_token'	=> $self -> {'access_token'},
		}
	);

	if ( $res_code ) {
		my $data = decode_json($res_data);

		return $data;
	}
	else {
		$self->{'error'} = "Query has returned error: " . $res_data;
		return undef;
	};
}



=head2	Paypal_openid::get_error

	Get last error string

	Usage:
		my $err_string = $ppa->get_error;

	Return:
		String with explanation of last error
=cut
sub get_error {
	my ( $self ) = @_;

	return $self->{'error'};
}


# _____ PRIVATE METHODS _____ #


sub _http_query {
	my ( $query_url, $query_method, $query_params ) = @_;
	
	my $user_agent  = LWP::UserAgent->new();

	my $response = $user_agent->$query_method( $query_url, $query_params );

	return ( 0, 'STATUS: ' . $response->status_line() 
		. ' ERROR: ' . $response->content )
	if $response->is_error;

	return (1, $response->content);
}

1;
