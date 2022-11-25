use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'RaffiWare::APIUtils',
    VERSION_FROM      => 'lib/RaffiWare/APIUtils.pm', 
    PREREQ_PM         => {
      'Module::Load::Conditional' => 0,
      'Crypt::Random'             => 0,
      'URI'                       => 0,
      'DateTime'                  => 0,
      'Data::UUID'                => 0,
      'DateTime::Format::ISO8601' => 0,
      'MIME::Base64'              => 0,
      'Time::HiRes'               => 0,
      'Try::Tiny'                 => 0,
      'UUID4::Tiny'               => 0,
      'Crypt::PK::RSA'            => 0  
    }, 
    "TEST_REQUIRES" => {
      "ExtUtils::MakeMaker" => 0,
      "Test::Deep" => 0,
      "Test::More" => "0.92"
    },
    "test" => {
      "TESTS" => "t/*.t"
    },
    ABSTRACT_FROM     => 'lib/RaffiWare/APIUtils.pm',
    AUTHOR            => 'RaffiWare  <dev@raffiware.io>',
    LICENSE           => 'mit',
);
