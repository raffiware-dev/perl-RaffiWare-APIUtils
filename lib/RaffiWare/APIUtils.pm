package RaffiWare::APIUtils;

use strict;
use warnings;

our $RSA_MODULE;

BEGIN {
  use Module::Load::Conditional qw|can_load|;

  $RSA_MODULE = 'Crypt::Perl';

  if ( can_load( module => { 'Crypt::PK::RSA' => 0 } ) ) {
    $RSA_MODULE = 'Crypt::PK::RSA';
  }

  Module::Load::load($RSA_MODULE);
}

# Keep compat with FatPacker
use Carp;
use Crypt::Random qw| makerandom_itv |;
use URI;
use DateTime;
use Data::UUID;
use DateTime::Format::ISO8601;
use MIME::Base64;
use POSIX       qw(strftime);
use Digest::SHA qw|sha256_hex|;
use Time::HiRes qw(time);
use Try::Tiny;
use UUID4::Tiny qw| create_uuid uuid_to_string |;
use Data::Dumper;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT_OK = qw|

  sign_exc_request
  verify_exc_request
  verify_exc_tokens

  get_local_timezone
  get_local_datetime
  get_local_time_stamp
  get_utc_datetime
  get_utc_time_stamp
  inflate_iso8601_datetime
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
  get_canonical_host
|;

our $VERSION = '0.002001';
$VERSION = eval $VERSION;

my %RSA_FUNC_MAP = (
  'Crypt::PK::RSA' => {
    new => sub { Crypt::PK::RSA->new( \$_[0] ); },

    # Configuring from compatibility with jsrsasign SHA256withRSAandMGF1 algorithm. See:
    #   https://kjur.github.io/jsrsasign/api/symbols/KJUR.asn1.x509.AlgorithmIdentifier.html
    #
    sign => sub {
      my ( $key, $msg ) = @_;
      $key->sign_message( $msg, 'SHA256', 'pss', 32 );
    },    #, 'v1.5'); },
    verify => sub {
      my ( $key, $sig, $msg ) = @_;
      $key->verify_message( $sig, $msg, 'SHA256', 'pss', 32 );
    }     #, 'v1.5' ); }
  },
  'Crypt::Perl' => {

    #  my $prkey1 = Crypt::Perl::RSA::Parse::private($pem_or_der);
    #  my $pbkey1 = Crypt::Perl::RSA::Parse::public($pem_or_der);
    #
    #  #----------------------------------------------------------------------
    #
    #  my $prkey = Crypt::Perl::RSA::Generate::generate(2048);
    #
    #  my $der = $prkey->to_der();
    #  my $der2 = $prkey->to_pem();
    #
    #  #----------------------------------------------------------------------
    #
    #  my $msg = 'My message';
    #
    #  my $sig = $prkey->sign_RS256($msg);
    #
    #  die 'wrong' if !$prkey->verify_RS256($msg, $sig);
  },
);

# Has and Sign message body
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

  my $nonce;
  $nonce .= int( gen_secure_rand(99) ) for ( 1 .. 5 );

  return {
    'Content'       => sha256_hex($content),
    'KeyID'         => $key_id,
    'Nonce'         => $nonce,
    'RequestMethod' => lc $req->method,
    'Resource'      => get_canonical_host($url),
    'ResourcePath'  => $url->path_query,
    'TimeOffset'    => $offset // 0,
    'TimeStamp'     => get_utc_time_stamp(),
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
    croak("Missing Header: $_")
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

sub verify_exc_tokens {
  my ( $tokens, $enc_sig, $pub_key_string ) = @_;

  my $key = $RSA_FUNC_MAP{$RSA_MODULE}->{new}->($pub_key_string);
  my $msg = msg_from_tokens($tokens);

  my $sig = decode_base64($enc_sig);

  return $RSA_FUNC_MAP{$RSA_MODULE}->{verify}->( $key, $sig, $msg );
}

sub gen_signature {
  my ( $key_string, $tokens ) = @_;

  my $key = $RSA_FUNC_MAP{$RSA_MODULE}->{new}->($key_string);
  my $msg = msg_from_tokens($tokens);
  my $sig = $RSA_FUNC_MAP{$RSA_MODULE}->{sign}->( $key, $msg );

  return encode_base64( $sig, '' );
}

sub msg_from_tokens {
  my $tokens = shift;

  return join( ',', map { $tokens->{$_} } sort { $a cmp $b } keys %$tokens );
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

sub gen_secure_rand {
  my $upper = shift;

  return makerandom_itv(
    Upper    => $upper,
    Size     => 256,
    Strength => 1
  );
}

our $LOCALTZ = DateTime::TimeZone->new( name => 'local' );

sub get_local_timezone { return $LOCALTZ; }

sub get_timestamp_iso8601 {
  my ($dt) = @_;

  return if !$dt;

  $dt->set_time_zone( get_local_timezone() )
    if $dt->time_zone()->name eq 'floating';

  my $tz = $dt->strftime('%z');
  $tz =~ s/(\d{2})(\d{2})/$1:$2/;

  return $dt->strftime("%Y-%m-%dT%H:%M:%S.%3N") . $tz;
}

sub get_local_datetime {

  my $t  = time;
  my $ns = int( ( $t - int($t) ) * 1_000_000_000 );

  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime($t);

  my $dt_now = DateTime->new(
    year       => $year + 1900,
    month      => $mon + 1,
    day        => $mday,
    hour       => $hour,
    minute     => $min,
    second     => $sec,
    nanosecond => $ns,
    time_zone  => $LOCALTZ,
  );

  return $dt_now;
}

sub get_local_time_stamp { return get_timestamp_iso8601( get_local_datetime() ) }

sub get_utc_datetime {

  my $t  = time;
  my $ns = int( ( $t - int($t) ) * 1_000_000_000 );

  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = gmtime($t);

  my $dt_now = DateTime->new(
    year       => $year + 1900,
    month      => $mon + 1,
    day        => $mday,
    hour       => $hour,
    minute     => $min,
    second     => $sec,
    nanosecond => $ns,
    time_zone  => 'UTC',
  );

  return $dt_now;
}

sub get_utc_time_stamp { return get_timestamp_iso8601( get_utc_datetime() ) }

sub inflate_iso8601_datetime {
  my ($datetime_str) = @_;

  my $base_dt = DateTime->now->set_time_zone('floating');
  my $iso8601 = DateTime::Format::ISO8601->new( base_datetime => $base_dt );

  my $dt = try { $iso8601->parse_datetime($datetime_str) }
  catch { croak("Invalid DateTime $datetime_str : $_"); };

  return $dt;
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
