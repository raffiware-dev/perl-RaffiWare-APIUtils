package RaffiWare::APIUtils::DateTime;

use strict;
use warnings; 

use Carp;
use Time::HiRes;
use Time::Piece; 
use Try::Tiny;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT_OK = qw|

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

sub get_local_timezone { 

   load_DateTime();
   return DateTime::TimeZone->new( name => 'local' ); 
}

sub get_timestamp_iso8601 {
  my ($dt, $mil) = @_;

  return if !$dt;

  if ( ref($dt) eq 'DateTime' ) { 

    $dt->set_time_zone( get_local_timezone() )
      if $dt->time_zone()->name eq 'floating';

    my $tz = $dt->strftime('%z');
    $tz =~ s/(\d{2})(\d{2})/$1:$2/;

    return $dt->strftime("%Y-%m-%dT%H:%M:%S.%3N") . $tz;
  }
  elsif ( ref($dt) eq 'Time::Piece' ) {

     my $tz = $dt->strftime('%z');
     $tz =~ s/(\d{2})(\d{2})/$1:$2/; 

     $mil ||= '';

     return  $dt->strftime('%Y-%m-%dT%H:%M:%S' ) . $mil . $tz; 
  }

  croak "$dt unsupported";
}

sub get_local_datetime {

  load_DateTime();

  my $t  = Time::HiRes::time();
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
    time_zone  => DateTime::TimeZone->new( name => 'local' ),
  );

  return $dt_now;
}

sub get_local_time_stamp { return get_timestamp_iso8601( get_local_datetime() ) }

sub get_utc_timepiece { 
  my $tp = gmtime(); 

  return wantarray ? ($tp, Time::HiRes::time() =~ /(\.\d{3})\d*$/) : $tp; 
} 

sub get_utc_datetime {

  load_DateTime(); 

  my $t  = Time::HiRes::time();
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

sub get_utc_time_stamp_tp { return get_timestamp_iso8601( get_utc_timepiece() ) }

sub inflate_iso8601_datetime {
  my ($datetime_str) = @_;

  load_DateTime(); 

  my $base_dt = DateTime->now->set_time_zone('floating');
  my $iso8601 = DateTime::Format::ISO8601->new( base_datetime => $base_dt );

  # failed nanoseconds
  # 2024-06-17T08:44:21.067-07:00
  # 2024-06-17T08:44:21.134-07:00
  # 2024-06-17T08:44:21.267-07:00
  # 2024-06-17T08:44:21.268-07:00
  # 2024-06-17T08:44:21.534-07:00
  # 2024-06-17T08:44:21.535-07:00
  # 2024-06-17T08:44:21.536-07:00 

  my $dt = try { $iso8601->parse_datetime($datetime_str) }
           catch { die("Invalid DateTime $datetime_str : $_\n"); };

  return $dt;
}

sub inflate_iso8601_timepiece {
  my ($ts_str) = @_;

  # Time::Piece doesn't support milliseconds
  # and the timezone offset cannot contain a ":"
  $ts_str =~ s/(?:\.\d{3})?([+-]\d{2}):(\d{2})$/$1$2/; 

  return Time::Piece->strptime($ts_str, '%Y-%m-%dT%H:%M:%S%z' );  
}

# Doubles memory usage to use these 
# so we lazy load them only in functions
# that need them.
sub load_DateTime {

 try {
   require DateTime;
   require DateTime::Format::ISO8601; 
   require Time::HiRes;
   Time::HiRes->import(qw|time|); 
 }
 catch {
   Carp::confess($_);
 }
} 
