use strict;
use warnings;

use Test::More;

use RaffiWare::APIUtils qw| 
  get_dh_encryptor 
  encrypt_with_secret 
  decrypt_with_secret 
  get_shared_secret_from_keys
|;

use Crypt::PK::X25519;  
use Data::Dumper;
use JSON qw| encode_json decode_json |;
use HTTP::Request::Common;

my $their_dh_pk  = Crypt::PK::X25519->new->generate_key; 

my  ( $our_dh_pub, $decryptor, $encryptor, $our_dh ) = get_dh_encryptor($their_dh_pk);

my $encipher = 'My super secret';
my $cipher = $encryptor->($encipher);

like( $cipher, qr/^[A-Za-z0-9_-]+$/, 'got cipher back');

my $plain = $decryptor->($cipher);

is $plain, $encipher, 'got original plain text back';

my $secret =  get_shared_secret_from_keys($their_dh_pk, $our_dh_pub);

is decrypt_with_secret($cipher, $secret), 'My super secret', 'got original from shared secret';

done_testing();
 
