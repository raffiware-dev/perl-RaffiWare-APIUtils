use strict;
use warnings;

use Test::Most;

use RaffiWare::APIUtils qw| verify_exc_key verify_exc_key_and_signer decode_bin encode_bin |;

use Data::Dumper;
use JSON qw| encode_json decode_json |;
use HTTP::Request::Common;

my $authority = 'MCowBQYDK2VwAyEARLnBpRRjIxqxE0FddA5jMbKZEGcpRmBEmGlQHniKjrc';

my $key_data = {
  'owner_id'    => 'test_27a46876443f4b2d99b4de95b6c4decc',
  'public_key'  => 'MCowBQYDK2VwAyEAFeU5uD_7HykSAeElcwSucvUZ1dspjQSEmzd8cG-DosU',
  'private_key' => 'MC4CAQAwBQYDK2VwBCIEIGkRcSbcC61XwPlfEGaX400kYklLatdK1b5y-WL7wmaU',
  'signed_by'   => {
    'expires'    => '2027-09-14T06:51:16.655+00:00',
    'signature'  => 'E5mDAV4Yq2bvdNVS4vsDEGlL-0VvEePcAKPmDgtq1-NNWbgr_xf66EYRsnMJhC3BC_tmaZDnkfL1p3PMB27iBA',
    'id'         => 'cak_4229e32d19514534beee764d6779010a',
    'signed_by'  => 'cak_74a2998712174ea8a7b4d34cce940009',
    'owner_id'   => 'ca_4229e32d19514534beee764d67790000',
    'public_key' => 'MCowBQYDK2VwAyEABdSIdW4J0MYLbY7g2hEzvlYxMHJwKmoinzuqjaoxNh4',
    'context'    => undef,
    'created'    => '2025-09-14T06:51:16.655+00:00'
  },
  'id'        => 'testk_d7c61a7d6a854319847d3a799ff98a18',
  'signature' => '1-I35nkyEXWxBJCiaWcDtG2rRxt3Mn8xAVnLvViyOylcxdsbGEK-6oMd1rAWdtaTlqqlf9iclLkz2zgF3F8KCw',
  'expires'   => '2026-09-23T08:25:24.331+00:00',
  'created'   => '2025-09-23T08:25:24.331+00:00',
  'context'   => {
    'api' => 'testing'
  }
};


ok( verify_exc_key($key_data, $key_data->{signature}, $key_data->{signed_by}->{public_key}), 
    'key verifed' );

# Signer is the self signed root authority.
ok( verify_exc_key_and_signer( $key_data, $authority ), 'key and signer verifed' ); 

throws_ok(
  sub {  
    verify_exc_key(
      $key_data, 
      $key_data->{signature}, 
      $key_data->{signed_by}->{public_key}, 
      { $key_data->{id} => 1 }
     ), 
  },
  qr/Invalid Key/
);

my $key_data_bad = {
  created     => '2025-06-11T20:31:24.712+00:00',
  expires     => '2027-06-11T20:30:24.712+00:00',
  id          => 'cak_1aa701fb08a34a798ba21e7bd1cd010a',
  owner_id    => 'ca_1aa701fb08a34a798ba21e7bd1cd0000',
  private_key => 'MC4CAQAwBQYDK2VwBCIEIA6IX-Ko8BojjG9b-DzaO_O66PdUbRc7O-TRHt6_mQSv',
  public_key  => 'MCowBQYDK2VwAyEAwynG_tsFRxSLXk0hVUp0_G0fK94CjxyUoQ6otkW8ZV4',
  signature   => 'jeAx2Nc4D252UYfgkiQbaxefSnN6aotnQVTuKtZJRwELw5i32yyO3FrvE8VSpumAQv38kz4U0QxKxg0mS851Cw',
  signed_by   => { 
    'expires' => '2027-09-14T06:51:16.655+00:00',
    'signature' => 'E5mDAV4Yq2bvdNVS4vsDEGlL-0VvEePcAKPmDgtq1-NNWbgr_xf66EYRsnMJhC3BC_tmaZDnkfL1p3PMB27iBA',
    'id'        => 'cak_4229e32d19514534beee764d6779010a',
    'signed_by' => 'cak_74a2998712174ea8a7b4d34cce940009',
    'owner_id' => 'ca_4229e32d19514534beee764d67790000',
    'public_key' => 'MCowBQYDK2VwAyEABdSIdW4J0MYLbY7g2hEzvlYxMHJwKmoinzuqjaoxNh4',
    'context' => undef,
    'created' => '2025-09-14T06:51:16.655+00:00' 
  }
}; 

throws_ok(
  sub {  
    verify_exc_key($key_data_bad, $key_data->{signature}, $key_data->{signed_by}->{public_key}), 
  },
  qr/^Key Validation Failed/
); 

throws_ok(
  sub { 
    verify_exc_key_and_signer(
      $key_data_bad, 
      $key_data_bad->{signed_by}->{public_key}
    );
  },
  qr/^Signer Verification Failed/
);

my $key_data_expired = {
  created     => '2020-06-11T20:31:24.712+00:00',
  expires     => '2023-06-11T20:30:24.712+00:00',
  id          => 'cak_1aa701fb08a34a798ba21e7bd1cd010a',
  owner_id    => 'ca_1aa701fb08a34a798ba21e7bd1cd0000',
  private_key => 'MC4CAQAwBQYDK2VwBCIEIA6IX-Ko8BojjG9b-DzaO_O66PdUbRc7O-TRHt6_mQSv',
  public_key  => 'MCowBQYDK2VwAyEAwynG_tsFRxSLXk0hVUp0_G0fK94CjxyUoQ6otkW8ZV4',
}; 

throws_ok(
  sub {  
   verify_exc_key($key_data_expired, '', '');
  },
  qr/Expired/
); 

done_testing();
