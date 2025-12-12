use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'RaffiWare::APIUtils',
    VERSION_FROM      => 'lib/RaffiWare/APIUtils.pm', 
    PREREQ_PM         => {
      'URI'                       => 0,
      'Data::UUID'                => 0,
      'MIME::Base64'              => 0,
      'Try::Tiny'                 => 0,
      'UUID4::Tiny'               => 0,
      'Crypt::PK::Ed25519'        => 0,
      'Crypt::PK::X25519'         => 0,
      'Crypt::AuthEnc::GCM'       => 0, 
      'Crypt::PRNG'               => 0, 
      'Crypt::KeyDerivation'      => 0,
      'HTTP::Request::Common'     => 0, 
      'DateTime'                  => 0, 
      'DateTime::Format::ISO8601' => 0, 

    }, 
    "TEST_REQUIRES" => {
      "ExtUtils::MakeMaker" => 0,
      "Test::Deep" => 0,
      "Test::More" => "0.92",
      "Test::Most" => 0
    },
    "test" => {
      "TESTS" => "t/*.t"
    },
    META_MERGE => {
       "meta-spec" => { version => 2 },
       provides => {
           'RaffiWare::APIUtils'           => { file => 'lib/RaffiWare/APIUtils.pm' },
           'RaffiWare::APIUtils::DateTime' => { file => 'lib/RaffiWare/APIUtils/DateTime.pm' },
       },
    },
    ABSTRACT_FROM     => 'lib/RaffiWare/APIUtils.pm',
    AUTHOR            => 'RaffiWare  <dev@raffiware.io>',
    LICENSE           => 'mit',
);
