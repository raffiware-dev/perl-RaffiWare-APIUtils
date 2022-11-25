use strict;
use warnings;

use Test::More;

use RaffiWare::APIUtils qw| get_utc_datetime
                            get_local_datetime
                            get_local_time_stamp 
                            get_local_timezone 
                            get_utc_time_stamp 
                            get_timestamp_iso8601 
                            inflate_iso8601_datetime   | ;

my $utc_dt = get_utc_datetime();
isa_ok( $utc_dt, 'DateTime' );

my $utc_ts = get_utc_time_stamp();
diag('UTC '. $utc_ts);      


my $local_dt = get_local_datetime();
isa_ok( $local_dt, 'DateTime' );

my $tz = get_local_timezone();
diag('local tz '. $tz); 

my $local_ts = get_local_time_stamp(); 
diag("\nlocal time ". $local_ts);


my $ts = '2022-11-27T22:52:20.325+00:00';
my $dt = inflate_iso8601_datetime($ts);

isa_ok( $dt, 'DateTime' );

my $iso_timestamp = get_timestamp_iso8601($dt); 

is $iso_timestamp, $ts, 'got timestamp back';

done_testing(); 
