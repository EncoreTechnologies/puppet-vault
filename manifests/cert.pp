# @summary a vault certificate that also amanges the ownership and mode of the generated
#          certificate files (for use on Linux)
define vault::cert (
  String  $ensure,
  String  $api_server,
  String  $api_token,
  String  $secret_role,
  Optional[String] $common_name     = $title,
  Optional[String] $alt_names       = undef,
  Optional[String] $ip_sans         = undef,
  # API options
  Optional[Integer] $api_port       = undef,
  Optional[String] $api_scheme      = undef,
  # Cert options
  Optional[String] $cert            = undef,
  Optional[String] $cert_dir        = undef,
  String $cert_group                = 'root',
  String $cert_owner                = 'root',
  Stdlib::Filemode $cert_mode       = '0644',
  Optional[String] $cert_name       = $title,
  Optional[String] $cert_ttl        = undef,
  # Private Key options
  Optional[String] $priv_key        = undef,
  Optional[String] $priv_key_dir    = undef,
  Optional[String] $priv_key_group  = undef,
  Optional[String] $priv_key_owner  = undef,
  Stdlib::Filemode $priv_key_mode   = '0600',
  Optional[String] $priv_key_name   = undef,
  # File options
  Boolean $manage_files             = true,
  Optional[Integer] $regenerate_ttl = undef,
  Optional[String]  $secret_engine  = undef,
) {
  vault_cert { $title:
    ensure         => $ensure,
    cert_name      => $cert_name,
    cert_dir       => $cert_dir,
    cert           => $cert,
    priv_key_name  => $priv_key_name,
    priv_key_dir   => $priv_key_dir,
    priv_key       => $priv_key,
    api_server     => $api_server,
    api_port       => $api_port,
    api_scheme     => $api_scheme,
    api_token      => $api_token,
    common_name    => $common_name,
    alt_names      => $alt_names,
    cert_ttl       => $cert_ttl,
    regenerate_ttl => $regenerate_ttl,
    secret_engine  => $secret_engine,
    secret_role    => $secret_role,
  }

  if $manage_files and $facts['os']['family'] != 'windows' {
    file { Vault_cert[$title]['cert_path']:
      ensure    => $ensure,
      owner     => $cert_owner,
      group     => $cert_group,
      mode      => $cert_mode,
      subscribe => Vault_cert[$title],
    }
    $_priv_key_owner = pick($priv_key_owner, $cert_owner)
    $_priv_key_group = pick($priv_key_group, $cert_owner)
    file { Vault_cert[$title]['priv_key_path']:
      ensure    => $ensure,
      owner     => $_priv_key_owner,
      group     => $_priv_key_group,
      mode      => $priv_key_mode,
      subscribe => Vault_cert[$title],
    }
  }
}