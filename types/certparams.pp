type Vault::CertParams = Struct[
  {
    cert_name           => String,
    common_name         => String,
    api_secret_role     => String,
    api_server          => String,
    alt_names           => Optional[Array[String]],
    ip_sans             => Optional[Array[String]],
    api_auth_method     => Optional[String],
    api_auth_parameters => Optional[Hash],
    api_auth_path       => Optional[String],
    api_auth_token      => Optional[String],
    api_scheme          => Optional[String],
    api_port            => Optional[Integer],
    api_secret_engine   => Optional[String],
    cert_ttl            => Optional[String],
    regenerate_ttl      => Optional[Integer],
    serial_number       => Optional[String],
  }
]
