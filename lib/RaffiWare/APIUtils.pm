package RaffiWare::APIUtils;

use strict;
use warnings;


use Carp;

use Crypt::KeyDerivation 'hkdf'; 
use Crypt::PK::Ed25519;
use Crypt::PK::X25519; 
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes irand );

use JSON qw| decode_json encode_json |; 
use URI;
use Data::UUID;
use MIME::Base64 qw| encode_base64url decode_base64url |; 
use POSIX       qw(strftime);
use Digest::SHA qw|sha256_hex|;
use Try::Tiny;
use UUID4::Tiny qw| create_uuid uuid_to_string |;
use Data::Dumper;
use Time::Piece;


use RaffiWare::APIUtils::DateTime qw|
  get_local_timezone
  get_local_datetime
  get_local_time_stamp
  get_utc_datetime
  get_utc_timepiece
  get_utc_time_stamp
  get_utc_time_stamp_tp 
  inflate_iso8601_datetime
  inflate_iso8601_timepiece
  get_timestamp_iso8601
|;
require Exporter;

our @ISA = qw(Exporter);

our $VERSION = '1.001002';
$VERSION = eval $VERSION; 

our @EXPORT_OK = qw|

  sign_exc_request
  verify_exc_request
  verify_exc_response
  verify_exc_command
  verify_exc_key 
  verify_exc_key_and_signer
  verify_exc_tokens

  create_ed25519_keys
  create_x25519_keys 

  key_encoding
  stored_key_encoding 

  load_public_key
  get_dh_encryptor
  encrypt_with_secret
  decrypt_with_secret
  get_shared_secret_from_keys 

  get_local_timezone
  get_local_datetime
  get_local_time_stamp
  get_utc_datetime
  get_utc_timepiece
  get_utc_time_stamp
  get_utc_time_stamp_tp 
  inflate_iso8601_datetime
  inflate_iso8601_timepiece
  get_timestamp_iso8601

  gen_uuid
  gen_random_string
  gen_signature

  prefix_uuid
  unprefix_uuid
  parse_uri_uuid
  make_uri_uuid
  is_uuid

  msg_from_tokens
  tokens_from_msg
  gen_tokens_for_request
  get_request_tokens
  get_canonical_host

  encode_bin
  decode_bin

|;

our $PK_MODULE = 'Ed25519';
our $DH_MODULE = 'X25519'; 

my %PK_FUNC_MAP = (
  'Ed25519' => {
    new => sub {


    },
    load => sub { 

      my $key_data = \$_[0];
      try { Crypt::PK::Ed25519->new($key_data) }
      catch { Carp::confess($_) }; 

    },
    sign => sub {
      my ( $key, $msg ) = @_;
      $key->sign_message($msg);
    },
    verify => sub {
      my ( $key, $sig, $msg ) = @_;

      return  $key->verify_message( $sig, $msg );
    }
  }, 
  'X25519' => {
    new => sub { 
      return Crypt::PK::X25519->new->generate_key
    },
    load => sub {
      my $key_data = \$_[0];
      try { Crypt::PK::X25519->new($key_data) }
      catch { Carp::confess($_) };  
    },
    shared_secret => sub {
      my ( $key, $other_pk ) = @_;

      return $key->shared_secret($other_pk); 
    }
  },
);


sub create_ed25519_keys {

  my $pk = Crypt::PK::Ed25519->new();

  $pk->generate_key();

  my $public_der = encode_bin($pk->export_key_der('public'));

  return ( $public_der, $pk );
} 

sub create_x25519_keys {

  my $pk = Crypt::PK::X25519->new();

  $pk->generate_key();

  my $public_der = encode_bin($pk->export_key_der('public'));

  return ( $public_der, $pk );
}

sub sign_exc_request {
  my ( $key_id, $req, $key_string, $offset ) = @_;

  my $tokens = gen_tokens_for_request( $key_id, $req, $offset );

  $req->header( 'X-EXC-KeyID'      => $tokens->{KeyID} );
  $req->header( 'X-EXC-TimeStamp'  => $tokens->{TimeStamp} );
  $req->header( 'X-EXC-TimeOffset' => $tokens->{TimeOffset} );
  $req->header( 'X-EXC-Nonce'      => $tokens->{Nonce} );
  $req->header( 'X-EXC-Signature'  => gen_signature( $key_string, $tokens ) );

  return wantarray ? ( $req, $tokens ) : $req;
}

sub gen_tokens_for_request {
  my ( $key_id, $req, $offset ) = @_;

  my $url = URI->new( $req->uri );

  my $content = $req->content || '';

  my $nonce = irand();

  return {
    'Content'       => sha256_hex($content),
    'KeyID'         => $key_id,
    'Nonce'         => $nonce,
    'RequestMethod' => lc $req->method,
    'Resource'      => get_canonical_host($url),
    'ResourcePath'  => $url->path_query,
    'TimeOffset'    => $offset // 0,
    'TimeStamp'     => get_utc_time_stamp_tp(),
  };
}

sub get_canonical_host {
  my $url = shift;

  my ($full_host) = $url->canonical =~ qr|^(https?://[^/]+)|;

  return $full_host;
}

sub verify_exc_request {
  my ( $req, $pub_key_string ) = @_;

  my @required = qw| 
    X-EXC-KeyID
    X-EXC-Signature
    X-EXC-TimeStamp
    X-EXC-TimeOffset
    X-EXC-Nonce
  |;

  foreach (@required) {
    die("Missing Header: $_\n")
      if !defined $req->header($_);
  }

  my $url = URI->new( $req->uri );

  my %tokens = (
    'Content'       => sha256_hex( $req->content || '' ),
    'KeyID'         => $req->header('X-EXC-KeyID'),
    'Nonce'         => $req->header('X-EXC-Nonce'),
    'RequestMethod' => lc $req->method,
    'Resource'      => get_canonical_host($url),
    'ResourcePath'  => $url->path_query,
    'TimeOffset'    => $req->header('X-EXC-TimeOffset'),
    'TimeStamp'     => $req->header('X-EXC-TimeStamp'),
  );

  return verify_exc_tokens( \%tokens, $req->header('X-EXC-Signature'), $pub_key_string );
}

sub get_request_tokens {
  my $req = shift;

  my $url = URI->new( $req->uri );

  return {
    'Content'       => sha256_hex( $req->content || '' ),
    'KeyID'         => $req->header('X-EXC-KeyID'),
    'Nonce'         => $req->header('X-EXC-Nonce'),
    'RequestMethod' => lc $req->method,
    'Resource'      => get_canonical_host($url),
    'ResourcePath'  => $url->path_query,
    'TimeOffset'    => $req->header('X-EXC-TimeOffset'),
    'TimeStamp'     => $req->header('X-EXC-TimeStamp'),
  };
}

sub verify_exc_response {
  my ( $resp, $authority ) = @_;

  my $req_id  = $resp->header('x-exc-requestid'); 
  my $ts      = $resp->header('x-exc-timestamp');
  my $nonce   = $resp->header('x-exc-nonce');
  my $sig     = $resp->header('x-exc-signature');
  my $req_sig = $resp->request->header('x-exc-signature'); 

  my $signer_key_data = decode_json(decode_bin($resp->header('x-exc-key')));

  my $tokens = {
    Nonce     => $nonce,
    TimeStamp => $ts,
    RequestId => $req_id,
    Code      => $resp->code,
    $req_sig
       ? ( RequestSignature => $req_sig )
       : (),
    $resp->code != 204
      ? (  Body => sha256_hex($resp->content) )
      : ()
  }; 

  verify_exc_key_and_signer( $signer_key_data, $authority ) 
    or return;

  return verify_exc_tokens( $tokens, $sig, $signer_key_data->{public_key} );
} 

sub verify_exc_key_and_signer {
  my ( $key_data, $authority_pub, $revoked_keys ) = @_;

  my $signer_data = $key_data->{signed_by}; 
  my $signer_sig  = $signer_data->{signature};
  my $signer_pub  = $signer_data->{public_key}; 

  try {
    verify_exc_key( $signer_data, $signer_sig, $authority_pub, $revoked_keys )
  }
  catch {
    die("Signer Verification Failed: $_\n");
  };

  my $signature = $key_data->{signature};

  try { 
    verify_exc_key( $key_data, $signature, $signer_pub, $revoked_keys );
  }
  catch {
    die("Key Verification Failed: $_\n");
  }; 
}

sub verify_exc_key {
  my ($key_data, $sig, $signer_pub, $revoked_keys ) = @_;

  my $id         = $key_data->{id};
  my $owner_id   = $key_data->{owner_id};
  my $created_ts = $key_data->{created};
  my $expires_ts = $key_data->{expires};
  my $context    = $key_data->{context} || {};
  my $public_key = $key_data->{public_key}; 

  die("Invald Data\n") 
     unless ( $id && $owner_id && $created_ts && $expires_ts && $public_key );

  die("Invalid Key\n") if $revoked_keys && $revoked_keys->{$id};

  my $created_dt = inflate_iso8601_timepiece($created_ts);
  my $expires_dt = inflate_iso8601_timepiece($expires_ts); 
  my $now_dt     = get_utc_timepiece();

  die("Invalid Date  $created_dt > $now_dt \n") if $created_dt > $now_dt;
  die("Expired\n") if $now_dt > $expires_dt; 

  my $tokens = {
     id       => $id,
     owner_id => $owner_id,
     created  => $created_ts,
     expires  => $expires_ts,
     context  => msg_from_tokens($context),
     pub_key  => decode_bin($public_key)
  };

  die("Key Validation Failed\n") unless verify_exc_tokens( $tokens, $sig, $signer_pub );
}

sub verify_exc_command {
  my (%args) = @_;

  my $public_key = $args{public_key} or die("Missing Public Key\n");
  my $tokens = {
   map {
    defined $args{$_} or die("Missing Token $_\n");

    ( $_ => $args{$_} ) 
   }
   qw|
     instance_id
     site_id
     site_user_id
     created_ts
     command_string
     command_id
     key_id
   |
  };

  my $type = $args{execute_type};

  if ( $type eq 'script' ) {
    $tokens->{command_string} .= sha256_hex( $args{script_src} );
  }

  return verify_exc_tokens( $tokens, $args{'site_user_signature'}, $public_key ); 
}

sub load_public_key {
  my ( $pub_key_enc, $algorithm ) = @_; 

  $algorithm  ||= $PK_MODULE;

  my $der = decode_bin($pub_key_enc);

  return $PK_FUNC_MAP{$algorithm}->{load}->($der); 
}

sub encode_bin { return encode_base64url(shift); }
sub decode_bin { return decode_base64url(shift); }

sub verify_exc_tokens {
  my ( $tokens, $enc_sig, $pub_key_enc ) = @_;

  my $key = load_public_key($pub_key_enc);
  my $msg = msg_from_tokens($tokens);

  my $sig = decode_bin($enc_sig);

  return $PK_FUNC_MAP{$PK_MODULE}->{verify}->( $key, $sig, $msg );
}

sub gen_signature {
  my ( $key_string, $tokens ) = @_;

  my $der = decode_bin($key_string);

  my $key = $PK_FUNC_MAP{$PK_MODULE}->{load}->($der);
  my $msg = msg_from_tokens($tokens);

  my $sig = $PK_FUNC_MAP{$PK_MODULE}->{sign}->( $key, $msg );

  return encode_bin($sig);
}

sub msg_from_tokens {
  my $tokens = shift;

  return join( ',', map { $tokens->{$_} } 
                    sort { $a cmp $b } 
                    grep { $tokens->{$_} .'' ne '' } 
                    keys %$tokens );
}

sub tokens_from_msg {
  my $msg = shift;

  my ( $content, $key_id, $nonce, $request_method,
       $resource, $resource_path, $time_offset, $timestamp ) = split( ',', $msg );

  return {
    'Content'       => $content,
    'KeyID'         => $key_id,
    'Nonce'         => $nonce,
    'RequestMethod' => $request_method,
    'Resource'      => $resource,
    'ResourcePath'  => $resource_path,
    'TimeOffset'    => $time_offset,
    'TimeStamp'     => $timestamp
  };
}

sub get_dh_encryptor {
  my ( $their_dh_pk ) = @_;

  my $our_dh     = $PK_FUNC_MAP{$DH_MODULE}->{new}->();
  my $our_dh_pub = encode_base64url( $our_dh->export_key_der('public') );
  my $secret     = $PK_FUNC_MAP{$DH_MODULE}->{shared_secret}->($our_dh, $their_dh_pk);

  # enc_cipher, $secret
  my $decryptor = sub {
    return decrypt_with_secret( $_[0], $secret ); 
  };

  # value, secret, [salt]
  my $encryptor = sub {
    return encrypt_with_secret( $_[0], $secret, $_[1] );
  };

  return ( $our_dh_pub, $decryptor, $encryptor, $our_dh ); 
}

sub encrypt_with_secret {
  my ( $value, $secret, $salt ) = @_;

  $salt ||= random_bytes(32);

  my $key_salt = substr($salt, 0, 16); 
  my $iv_salt  = substr($salt, 16, 16); 

  my $key = hkdf($secret, $key_salt, 'SHA256', 16, "Content-Encoding: aes128gcm\x00" );
  my $iv  = hkdf($secret, $iv_salt,  'SHA256', 12, "Content-Encoding: nonce\x00");

  my ($cipher, $tag) = gcm_encrypt_authenticate( 'AES', $key, $iv, '', $value );

  return encode_base64url( $salt . $cipher. $tag );
}  

sub decrypt_with_secret {
  my ( $base64_enc, $secret ) = @_;  

  my $enc           = decode_base64url($base64_enc);
  my $cipher_length = length($enc) - 48; # 48 for salt + tag;

  my $salt   = substr($enc, 0, 32);
  my $cipher = substr($enc, 32, $cipher_length); 
  my $tag    = substr($enc, 32 + $cipher_length, 16);

  my $key_salt = substr($salt, 0, 16); 
  my $iv_salt  = substr($salt, 16, 16);

  my $key = hkdf($secret, $key_salt, 'SHA256', 16, "Content-Encoding: aes128gcm\x00" );
  my $iv  = hkdf($secret, $iv_salt, 'SHA256', 12, "Content-Encoding: nonce\x00"); 

  return gcm_decrypt_verify( 'AES', $key, $iv, '', $cipher, $tag ); 
} 

sub get_shared_secret_from_keys {
  my ($priv_pk, $pub_enc_der) = @_;

  my $ret = 
    try {
      my $der     = decode_base64url($pub_enc_der);
      my $edh_pk  = $PK_FUNC_MAP{$DH_MODULE}->{load}->($der);

      return $PK_FUNC_MAP{$DH_MODULE}->{shared_secret}->($priv_pk, $edh_pk);
    } 
    catch { 
      warn "DH ERROR: $_"
    };

  return $ret;
}

sub stored_key_encoding {
   my ($base64) = shift;  

   return key_encoding( decode_bin($base64) );
}

sub key_encoding {
   my ($enc) = shift;  

   return hex(unpack('H2', $enc));
}  

sub gen_uuid {

  return uuid_to_string(create_uuid);
}

sub gen_random_string {
  my ( $length, $chars ) = @_;

  $length ||= 16;
  $chars  ||= [ "A" .. "Z", "a" .. "z", 0 .. 9 ];

  my $string;
  $string .= $chars->[ rand @$chars ] for 1 .. $length;

  return $string;
}

sub prefix_uuid {
  my ( $prefix, $uuid ) = @_;

  ( my $ret = "${prefix}_" . $uuid ) =~ tr/-//d;

  return $ret;
}

sub unprefix_uuid {
  my $prefixed_uuid = shift;

  my ( $prefix, $suuid ) = split( '_', $prefixed_uuid || '', 2 );

  return if !$suuid or length $suuid != 32;

  my $uuid = join( '-', unpack( 'A8 A4 A4 A4 A12', substr( $suuid, -32 ) ) );

  wantarray ? ( $uuid, $prefix ) : $uuid;
}

sub is_uuid {
  my $uri_uuid = shift;

  return $uri_uuid =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
}

sub parse_uri_uuid {
  my $uri_uuid = shift;

  return $uri_uuid if is_uuid($uri_uuid);

  ($uri_uuid) = lc($uri_uuid) =~ /^(?:[a-z]+_)?([a-f0-9]{32})$/
    or return;

  return join( '-', unpack( 'A8 A4 A4 A4 A12', $uri_uuid ) );
}

sub make_uri_uuid {
  my $uuid = shift;

  ( my $ret = $uuid ) =~ tr/-//d;

  return $ret;
}


1;
__END__

=head1 NAME

RaffiWare::APIUtils - Utilities for interacting with ExCollect service API

=head1 SYNOPSIS

  use ExCollect-APIUtils;

=head1 DESCRIPTION

  RaffiWare utility class.

=head1 AUTHOR

RaffiWare, E<lt>dev@raffiware.io<gt>

=head1 COPYRIGHT

Copyright (C) 2025 by RaffiWare

=head1 LICENSE

The MIT License

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to
whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

=head2 AVAILABILITY

The most current version of App::dec can be found at L<>

=cut 



=cut
