requires 'URI';
requires 'Data::UUID';
requires 'MIME::Base64';
requires 'Try::Tiny';
requires 'UUID4::Tiny';
requires 'Crypt::PK::Ed25519';
requires 'Crypt::PK::X25519';
requires 'Crypt::AuthEnc::GCM';
requires 'Crypt::PRNG';
requires 'Crypt::KeyDerivation';
requires 'JSON';
requires 'HTTP::Request::Common';
requires 'DateTime';
requires 'DateTime::Format::ISO8601';

on 'develop' => sub {
  requires 'Test::Most';
  requires 'JSON';
  requires 'HTTP::Request::Common';
};

on 'test' => sub {
    test_requires 'Test::More';
    test_requires 'Test::Most'; 
}; 

