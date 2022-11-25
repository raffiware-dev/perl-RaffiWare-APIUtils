requires 'Module::Load::Conditional';
requires 'Crypt::Random';
requires 'URI';
requires 'DateTime';
requires 'Data::UUID';
requires 'DateTime::Format::ISO8601';
requires 'MIME::Base64';
requires 'Time::HiRes';
requires 'Try::Tiny';
requires 'UUID4::Tiny';
requires 'Crypt::PK::RSA';
requires 'JSON';

on 'develop' => sub {
  requires 'JSON';
  requires 'HTTP::Request::Common';
};

