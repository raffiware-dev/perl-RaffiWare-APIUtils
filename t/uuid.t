use strict;
use warnings;

use Test::More;

use RaffiWare::APIUtils qw| gen_uuid make_uri_uuid parse_uri_uuid
                            prefix_uuid unprefix_uuid  is_uuid |;

use Data::Dumper;
use HTTP::Request::Common;


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

ok is_uuid( gen_uuid() ),         'is_uuid';
ok !is_uuid('blahasdf2340s2343'), 'is_uuid';

done_testing(); 
