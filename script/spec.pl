
use ExCollect::APIUtils qw| gen_signature msg_from_tokens verify_exc_tokens |;
use MIME::Base64;  

my $pub_key = '-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzhix/APPHjp/nb3T6BDY
fGH0BvOP9/o0hqz1ZAPyiPLNIHZLXzFpggkJU8BhLUxSGEorN1MzrUMbzRReCxXb
j4FyTumEU/lm7xZD2EZktOJaZdCWcZqY8B95dyhNMLOcVlakzmHAD66sa6QcH2nl
oRfeJXs79kVks9MvEp9wUVs5m56yCbAvFLcTvLZJjifItnF9pqySRSzULAgrBymd
uT8QKr4SiAmw28wmxrXTQcGBEu6kiqrApFNhP1Pqyn3wpxOABWTIKk3+ABq4YTue
rbJ56tNbiqv8hp7ieW4J20mQnL1ML0ZfKoP/NCc8TKG4bqdbI4Kif8iYEUB6fcf4
KwIDAQAB
-----END RSA PUBLIC KEY-----';

my $priv_key = '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzhix/APPHjp/nb3T6BDYfGH0BvOP9/o0hqz1ZAPyiPLNIHZL
XzFpggkJU8BhLUxSGEorN1MzrUMbzRReCxXbj4FyTumEU/lm7xZD2EZktOJaZdCW
cZqY8B95dyhNMLOcVlakzmHAD66sa6QcH2nloRfeJXs79kVks9MvEp9wUVs5m56y
CbAvFLcTvLZJjifItnF9pqySRSzULAgrBymduT8QKr4SiAmw28wmxrXTQcGBEu6k
iqrApFNhP1Pqyn3wpxOABWTIKk3+ABq4YTuerbJ56tNbiqv8hp7ieW4J20mQnL1M
L0ZfKoP/NCc8TKG4bqdbI4Kif8iYEUB6fcf4KwIDAQABAoIBAFvRGrIozEQuUZ5n
7JktsBSx2vKh3djfKjl5opVdQNcMPKCisu+E5vlcp0Adq+1vW/+gQ2KReatOA3u5
ADC2Gyvywocvd5mludr4M1+N9N21HgrQA8Y21r3bd9TDKqhwzEyWqzOazuLtsbj+
0tyX5AqBxKE0JsGPps6KXiVQzMwhJ/0l3GRjha6iHv4dGiaNCt/ZSL5bOQiUYO5+
p+l0CDipoQOEx1mYVBjxdwRe6iF1jQmbsnFrEW5TdTAWoYYMW/HjCB9N/nmF+pbu
en92ZrBLHM1bT0dZWJPbqGq7sRKlAL9Na+WlAr6ud4XlS/QxAzrYzqf+nVS7M923
Fi1bfYkCgYEA9l6mPD9el3dK1IkLsEyfo0y3Uo6LzTwwWol5Ut2OlRtoONLyPNpP
eKZS0DdY1eN8rhc9sTLE7uTENgsex4F6N0/PxF66K3JZk6ItVQusfiMiADQqY4eq
sCiIcn7QU+GXS7UdDfj3GqD7/95ks9hk6bYPfjr0LKjC++Lz16UN6l0CgYEA1icL
BG0kRQuKzEb7RVuY82Iz7vde93P2FmiLKIMBPtB8EZQxM/U5hnPNCbxsNyMxVBdH
Gj7998ETvJ3oXlB6J1whi+FA3OwaXM210kAPj091+kZibui9RtDJ85ekQyM61iK6
zvIB7iqHIKi5ehrz+gKRluFEk/15SkeK/IoiFCcCgYEA6RtrHIw0+wmDQw+cgKYv
UbqPpkx7mKf/dFqo8a/ybcCt3z4wt0U0doqgxqPnqRECclJJK/VGgmbwA9aHu+sV
cWpRwpKCggNDID4NuG9AOWUSkbDJ/rxp0x225OZ6RTOpDJgEMqlDXO2/Ij0ReV0h
NkTt6djsGalgPCZj48EnJn0CgYBhVJljR5+GafqJYXFuUnUvmOB1qaRV3zRndthY
b0IvpF3fN3UtYjTk8Nitph+g57PRvkqomRygb/ZicXpc80KxhOQSSSxLvFs29p++
kTMBNWIvf7HZKppsBxTiS3dytB5XmK1CxScvcdC8fTLfVkSwyl4VLwkWIcvwgJeg
s79NXQKBgBKFEp42nCiEFHvwtGIkkTNX9FFzMN/nLo7NqABOxXxySAnQCO5dKVy2
YHytd8jZc0XYDM0AtTWB13R9xWjBaOPrEhjamftrkyroNjL4TQ7OKpPE7cx5126h
yVK9QRgwtDDj/FhOAIEJ/mvCiftYf734hVVPFG8tWJfA8burwmsd
-----END RSA PRIVATE KEY-----';

my $tokens =  {
  Content       =>   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  KeyID         =>   'au_f259e486f3d3464e8367223400dfa3a8',
  Nonce         =>   3170017900,
  RequestMethod =>   'get',
  Resource      =>   'http://localhost',
  ResourcePath  =>   '/',
  TimeOffset    =>   2,
  TimeStamp     =>   '2024-03-08T21:01:40.179+00:00'
};


my $sig = gen_signature( $priv_key, $tokens );
my $msg = msg_from_tokens( $tokens );
my $b = encode_base64("hello world");


my $spec_sig =  'hN77aFCJiikM0lZZGPUU8bfEgAga7YL8U4Wj+J+TzeXDlsR/g0otCGVFRniYvrTZ+O0/sTuGXw/rhHRqS26B3a/GRENlnAk4LpoiLMCvzFbd3pfU+JxvPUj3wsdYPEy3exneYNHaP5h30VMgOu2xXeq4kfqmscAgp/qA5PWp2fN7KSSCePo4s3iBocFAZs5AnZj8RPuUqzFl2gTO5x4GUhLhvajGwExyZNZlZhHXpnExgpRN5OAIBJP7XLrsseC0tqYbzPVya2SIRrIqKEXzS6d/AmmFEOZUjVSi4+acYwWNZPHlDrZjhVLGMa0dFM6iVXp9LnOoyL593jLhrSz/WQ==' ;

my $pss_sig = 'NRtkGWm3MZICDc3rDsPP4iBWwNPwTnV2LiDvza1okpX87Q04djBvpkCdfDdcoacmUO8rF3F/ZJkidNIE55K+oJ8sCegRYeo1kVVzugjuFbHFEQp1BVSOKAAj3MFfR8tYz6Dtdlq3biMGl0LUZDG1p160c2Yscj98KnuquD+zRtSB8q4LJO7u0gUeBNOth6XVwWFX+LxehDtbeToRBap6S9qD0TZfdojOGgLFLhUA8NWDvBdqBVaxqLFykWd3u5eGrOeA765Hjd0zdz82xSkjkQ59C4HHx2lYNfHEd/u/qrAEd0ZveIY0H+OniGHl3lvwf76GzWnkctUHMf7EL7AYQA==';


my $ret = verify_exc_tokens( $tokens, $pss_sig, $pub_key );

print "sig: $ret\n";
