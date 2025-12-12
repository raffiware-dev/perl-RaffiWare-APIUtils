use strict;
use warnings;

use Test::More;
use Time::Piece; 

use RaffiWare::APIUtils qw| get_utc_datetime
                            get_local_datetime
                            get_local_time_stamp
                            get_local_timezone
                            get_utc_time_stamp
                            get_utc_time_stamp_tp
                            get_timestamp_iso8601
                            inflate_iso8601_datetime
                            inflate_iso8601_timepiece |;

my $utc_dt = get_utc_datetime();
isa_ok( $utc_dt, 'DateTime' );

my $utc_ts = get_utc_time_stamp();
diag( 'UTC DateTime ' . $utc_ts );

my $utc_short_ts = get_utc_time_stamp_tp();
diag( 'UTC TimePiece ' . $utc_short_ts ); 

my $local_dt = get_local_datetime();
isa_ok( $local_dt, 'DateTime' );

my $tz = get_local_timezone();
diag( 'local tz ' . $tz );

my $local_ts = get_local_time_stamp();
diag( "\nlocal time " . $local_ts );

my $ts = '2022-11-27T22:52:20.325+00:00';
my $dt = inflate_iso8601_datetime($ts);

isa_ok( $dt, 'DateTime' );

my $tp = inflate_iso8601_timepiece($ts); 

isa_ok( $tp, 'Time::Piece' ); 

my $iso_timestamp = get_timestamp_iso8601($dt);

is $iso_timestamp, $ts, 'got timestamp back';

my $iso_timestamp_from_tp = get_timestamp_iso8601($tp);
my $ts_from_tp            = '2022-11-27T22:52:20+00:00'; 

is $iso_timestamp_from_tp, $ts_from_tp, 'got timestamp back';
    

#$dt = $dt->subtract( seconds => 1, nanoseconds => $dt->nanosecond ); 
$dt = $dt->subtract( seconds => 1.7, nanoseconds => $dt->nanosecond );  

$iso_timestamp = get_timestamp_iso8601($dt); 

diag $local_ts;

my $fail_ts = '2025-05-17T20:44:20.134+00:00';

diag 'failed nanoseconds';
for ( 0..999  ) {

   local $@;
   my $fail_ts = sprintf("2024-06-17T08:44:21.%03d-07:00", $_); 
   eval { inflate_iso8601_datetime($fail_ts) };  

   diag $fail_ts if $@;
}

 my $p = ( defined( '134000000' )
            && !ref( '134000000' )
            && (
                   do {
                       my $val1 = '134000000';
                       $val1 =~ /\A-?[0-9]+(?:[Ee]\+?[0-9]+)?\z/
                       && $val1 == int($val1)
                       && '134000000' >= 0
                   }
               )  
          );

diag $p;

done_testing();
