use strict;
use warnings;

use Test::More;

use RaffiWare::APIUtils qw| sign_exc_request verify_exc_request
  gen_uuid prefix_uuid decode_bin |;

use Data::Dumper;
use JSON qw| encode_json decode_json |;
use HTTP::Request::Common;

my $priv_key =<<'END'; 
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBA81H73blYBLK+xheT+ITIAHwLoXYXNc3h15KoDDYmA
-----END PRIVATE KEY-----
END

my $priv_der = 'MC4CAQAwBQYDK2VwBCIEIBA81H73blYBLK-xheT-ITIAHwLoXYXNc3h15KoDDYmA';
my $pub_key =<<'END';
MCowBQYDK2VwAyEAwdzm-eDGVI3SOxrzfH5wwMtfN58umOZiSMRGC35ORes
END

my $key_id     = prefix_uuid( 't', gen_uuid() );
my $req        = GET('http://localhost/some/resource');
my $signed_req = sign_exc_request( $key_id, $req, $priv_der, 0 );

diag $signed_req->header('X-EXC-TimeStamp');

is( $signed_req->header('X-EXC-KeyID'), $key_id, 'KeyID header' );
ok( $signed_req->header('X-EXC-TimeStamp'),          'TimeStamp header' );
ok( defined $signed_req->header('X-EXC-TimeOffset'), 'TimeOffset header' );
ok( $signed_req->header('X-EXC-Signature'),          'Signature header' );

ok( verify_exc_request( $signed_req, $pub_key ), 'GET request verified' );

my @req_args = (
  'Content-type' => 'application/json;charset=utf-8',
  'Content'      => encode_json( { some => 'request', data => [qw| this that |] } )
);

$key_id     = prefix_uuid( 't', gen_uuid() );
$req        = POST( 'http://localhost/some/collection', @req_args );
$signed_req = sign_exc_request( $key_id, $req, $priv_der, 0 );

is( $signed_req->header('X-EXC-KeyID'), $key_id, 'KeyID header' );
ok( $signed_req->header('X-EXC-TimeStamp'),          'TimeStamp header' );
ok( defined $signed_req->header('X-EXC-TimeOffset'), 'TimeOffset header' );
ok( $signed_req->header('X-EXC-Signature'),          'Signature header' );

ok( verify_exc_request( $signed_req, $pub_key ), 'POST request verified' );

# Modified content after signing.
$signed_req->content( encode_json( { some => 'request_modified', data => [qw| this that |] } ) );
ok( !verify_exc_request( $signed_req, $pub_key ), 'request verified failed' );

$key_id     = prefix_uuid( 't', gen_uuid() );
$req        = GET( 'http://localhost/some/collection?search={"this":"that"}', @req_args );
$signed_req = sign_exc_request( $key_id, $req, $priv_der, 0 );

ok( verify_exc_request( $signed_req, $pub_key ), 'GET request with query verfied' );

$signed_req->uri('http://localhost/some/collection?search={"this":"those"}');
ok( !verify_exc_request( $signed_req, $pub_key ), 'GET request with altered query verify failed' );

$req = GET( 'http://localhost:8000/some/object#this', @req_args );
my $tokens;
( $signed_req, $tokens ) = sign_exc_request( $key_id, $req, $priv_der, 0 );

ok( verify_exc_request( $signed_req, $pub_key ), 'GET request with host:port verified' );

my $der = MIME::Base64::encode_base64url( Crypt::PK::Ed25519->new(\$priv_key)->export_key_der('private') );
#my $der = Crypt::PK::Ed25519->new(\decode_bin($priv_der))->export_key_pem('private'); 
diag $der;


done_testing();
