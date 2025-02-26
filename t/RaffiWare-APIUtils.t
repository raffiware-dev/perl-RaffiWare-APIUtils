use strict;
use warnings;

use Test::More;

BEGIN {
  my @test_exports = qw| 

    sign_exc_request
    verify_exc_request

    gen_uuid
    gen_random_string

    get_local_time_stamp
    get_local_timezone
    get_utc_time_stamp

    get_timestamp_iso8601
    inflate_iso8601_datetime

    prefix_uuid
    unprefix_uuid
    parse_uri_uuid
    make_uri_uuid
    is_uuid
  |;

  use_ok( 'RaffiWare::APIUtils', @test_exports );
}

use Data::Dumper;
use HTTP::Request::Common;

my $priv_key = '-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAspH2QB1pwa69AYJN48tdFsch96c/RjzCDDFObl8eyToZzidu
RM65vL/UabRB41L7u+Ugf5a12eLiq64Aeiyx6nVXGbdYKgst+O8hh49rtB2nvWHA
ltNcXY+UUHm+7sKg99X5pjuIhFls1Tx7wYT5DvQbTgldW2Il0p8DzgbUwb7Z4MGr
TqKLYZgmX3RRQZj5Rk3O0nJhp5nVSWdiz8lo2FUnqfPs9r4kJrQFwb0CHosB56Hg
DdB24X/MCR3hNMqKhTX1upDhNct0AF76yB73dbLiynsKayM9UDkwsuS53fTEfxzh
+XanzUbzcQWqvoZdNZyurWA+SgtBQEomcr/KGwIDAQABAoIBACqWYRJdcXF9yRnp
B8aCI8tg5pr3ykFoECd0Qu5TxTXco3blNIk4fFelsHUdRnF+wwbG2H9VZD14vPKQ
5xA8RJpULde2QFKWo/owneCEtf0Y7X5fJ91Qv0CZE5g10PGEfXteDtI0dJSL90bL
zAAVRIjqcvCjjx5SRA79WZzzSB6Ejdm5m4jkNLOtvYApgk63vOspMwvFosvdyFFI
UX6aiBB431xD3e1ElRd8uGdi/J5x0qYawq4LxPoAv+LVb46+VL8qZEKoJsdfdi+L
vjLNWYnwaSyObIqxy0uiHI2CvdF4py9z0JBQeRlseG9nKkTmKY0ARBLy3wcw0aMr
YEb9iTECgYEA1qY63745tuBbkpgyvy0K6qsNMBlWEtnSPpdHDeY+rBAE4zVz0OWg
Ut1IxMlDOfw9Bgb+UFWwB65BbWKjwYGxljKQfhVgfmfa8w4qKM1XaSsJJ5nBqwSR
FD/tLhnki/hDl2B1ay0YEv9UeZMj3ubKT+I4zmWVDIUzNQAapGFqTj0CgYEA1Phu
RZxFn1ddgxLYDQxdYqXEAcx1h63U4pw73jd4vhvtmsCkPO/TlUYdEDnFe/tqCgep
rJkhd0MisQJwQeVARZHZh0lDwUCN2GRmc7owaDTQh9fs0RVs0SbgZg5AXLysBca3
cw/VPRTfzntBdB31qkfczJslaLPHn24xe4r/lzcCgYEArsysQSzuXykSKa1cFiee
LkCh+ruHRs6v0lzrdjw8aW6aLFWJPWLiTtj5u5eS8ZOiNlhXniBJu9eCXIvpg1oU
vpXq6WKLNCVrPmgYmSWvu2tahy9FcfnEE9ODWPmpDvtcP9hDhsYwRrg7mM3kdk9I
DgnR7PL4kDug2dZ928OhCJkCgYBuu+26TBL3UtnQeU/VGQTFciOEO+cwcPYsDcgj
NvyU/LiCqn+7H4gIKbia4y8H1CXCqVFT6Rs5g7LaDsaHvMe6ZKeSbEnKheI7DZkn
uzvIMw3qVB9SZ6144pny9p4ImiFnr3dbYHQjmmL0Xaoe0iUWMN9hk5nT4wZ8ozMf
ZZqX6QKBgQCXtjMjdDGO5Mg8a9usgWRSrPRsza7YlqlMzheoZ6OjGdn4HAgokcKh
KLoQXLtx2Xuf5eoLP5z5LS+omJgtRHFvWQRbS46AMb4Rho3Bzyo96JiYRQu3MW+J
T/a54ZKV4sMRNTdiarXnJ5JiCmSsbyk1vc/02DTWjOO3WP2xnzBPYQ==
-----END RSA PRIVATE KEY-----';

my $pub_key = '-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAspH2QB1pwa69AYJN48td
Fsch96c/RjzCDDFObl8eyToZziduRM65vL/UabRB41L7u+Ugf5a12eLiq64Aeiyx
6nVXGbdYKgst+O8hh49rtB2nvWHAltNcXY+UUHm+7sKg99X5pjuIhFls1Tx7wYT5
DvQbTgldW2Il0p8DzgbUwb7Z4MGrTqKLYZgmX3RRQZj5Rk3O0nJhp5nVSWdiz8lo
2FUnqfPs9r4kJrQFwb0CHosB56HgDdB24X/MCR3hNMqKhTX1upDhNct0AF76yB73
dbLiynsKayM9UDkwsuS53fTEfxzh+XanzUbzcQWqvoZdNZyurWA+SgtBQEomcr/K
GwIDAQAB
-----END RSA PUBLIC KEY-----';

my $req        = GET('http://localhost/');
my $signed_req = sign_exc_request( 10, $req, $priv_key, 0 );

is( $signed_req->header('X-EXC-KeyID'), 10, 'KeyID header' );
ok( $signed_req->header('X-EXC-TimeStamp'),          'TimeStamp header' );
ok( defined $signed_req->header('X-EXC-TimeOffset'), 'TimeOffset header' );
ok( $signed_req->header('X-EXC-Signature'),          'Signature header' );

ok( verify_exc_request( $signed_req, $pub_key ), 'request verfied' );

my $uuid = gen_uuid();

is make_uri_uuid('7c89628f-6878-41ae-8911-7c8f850f633e'), '7c89628f687841ae89117c8f850f633e',
  'make uri_uuid';

is parse_uri_uuid('7c89628f687841ae89117c8f850f633e'), '7c89628f-6878-41ae-8911-7c8f850f633e',
  'uri_uuid parsed';

is parse_uri_uuid('av_8c89628f687841ae89117c8f850f633f'), '8c89628f-6878-41ae-8911-7c8f850f633f',
  'uri_uuid parsed with prefix';

is parse_uri_uuid('8c89628f-6878-41ae-8911-7c8f850f633f'), '8c89628f-6878-41ae-8911-7c8f850f633f',
  'uri_uuid parsed with uuid';

ok !defined parse_uri_uuid('somegarbab123'), 'bad uuid returns undef';

is prefix_uuid( 't', '7c89628f-6878-41ae-8911-7c8f850f633e' ),
  't_7c89628f687841ae89117c8f850f633e', 'prefi_uuid';

is unprefix_uuid('t_7c89628f687841ae89117c8f850f633e'), '7c89628f-6878-41ae-8911-7c8f850f633e',
  'unprefix_uuid scalar';

is_deeply [ unprefix_uuid('t_7c89628f687841ae89117c8f850f633e') ],
  [ '7c89628f-6878-41ae-8911-7c8f850f633e', 't' ], 'unprefix_uuid array';

ok !defined unprefix_uuid(), 'undef';

ok !defined unprefix_uuid('blahadsf2342'), 'undef';

diag( gen_random_string( 32, [ "A" .. "Z", "a" .. "z", 0 .. 9, split( '', '!#+,-./:=@_' ) ] ) );

ok is_uuid( gen_uuid() ),         'is_uuid';
ok !is_uuid('blahasdf2340s2343'), 'is_uuid';

done_testing();
