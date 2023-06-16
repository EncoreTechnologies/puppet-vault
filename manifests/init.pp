# @summary Full description of class vault here.
#
# @param api_addr
#   Specifies the address (full URL) to advertise to other Vault servers in the
#   cluster for client redirection. This value is also used for plugin backends.
#   This can also be provided via the environment variable VAULT_API_ADDR. In
#   general this should be set as a full URL that points to the value of the
#   listener address (Example: http://vault.domain.com:8200).
# @param arch
# @param bin_dir
#   Directory the vault executable will be linked to (Default: /usr/local/bin).
# @param config_dir
#   Directory the vault configuration will be kept in (Default: /etc/vault).
# @param config_mode
#   TODO (REMOVE) Mode of the configuration file (config.json) (Default: '0750').
#   Mode of the vault directories (Default: '0750').
# @param default_lease_ttl
# @param disable_cache
# @param disable_mlock
# @param domain
# @param download_dir
# @param download_extension
#   The extension of the vault download
# @param download_filename
# @param download_url
#   Manual URL to download the vault zip distribution from.
# @param download_url_base
#   Hashicorp base URL to download vault zip distribution from.
# @param enable_int_ca
# @param enable_ldap
# @param enable_root_ca
# @param enable_ui
# @param extra_config
# @param group
#   Customise the group vault runs as, will also create the user unless `manage_group` is false.
# @param ha_storage
# @param initialize_vault
#   If set to true, will initialize vault after installation.  Keys and tokens
#   are stored in $install_dir/vault_init.txt file.
# @param install_dir
#   The installation directory to install Vault to (Default: /opt/vault).
# @param install_method
# @param int_ca_config
# @param ip_address
# @param ldap_config
# @param ldap_groups
# @param listener
# @param manage_download_dir
# @param manage_file_capabilities
# @param manage_group
#   Whether or not the module should create the group.
# @param manage_service_file
# @param manage_service
#   Instruct puppet to manage service or not
# @param manage_storage_dir
# @param manage_user
#   Whether or not the module should create the user.
# @param max_lease_ttl
# @param min_keys
#   The minimum number of keys needed to unseal Vault (Default: 2).
# @param num_procs
#   Sets the GOMAXPROCS environment variable, to determine how many CPUs Vault
#   can use. The official Vault Terraform install.sh script sets this to the
#   output of ``nprocs``, with the comment, "Make sure to use all our CPUs,
#   because Vault can block a scheduler thread". Default: number of CPUs
#   on the system, retrieved from the ``processorcount`` Fact.
# @param os
# @param package_ensure
# @param package_name
# @param port
# @param published_url
#   URL applied to SSL certificates indicating CRL and CA distribution points.
#   Ex: http://vault.domain.com
# @param purge_config_dir
#   Whether the `config_dir` should be purged before installing the
#   generated config.
# @param root_ca_config
# @param seal
# @param service_enable
# @param service_ensure
# @param service_name
#   Customise the name of the system service
# @param service_options
#   Extra argument to pass to `vault server`, as per:
#   `vault server --help`
# @param service_provider
#   Customise the name of the system service provider; this
#   also controls the init configuration files that are installed.
# @param storage
# @param telemetry
# @param token
# @param total_keys
#   Specify the total number of keys created to unseal Vault (Default: 5).
# @param user
#   Customise the user vault runs as, will also create the user unless `manage_user` is false.
# @param vault_keys
# @param vault_policies
# @param version
#   The version of Vault to install
# @param manage_vault_utils
#
# Parameters
# ----------
# * `manage_vault_utils`
#   Instruct puppet to manage the additional utilities like openssl and jq
#
# == PKI Options
# * cert_params options
#   The following are optional parameters that can be passed to vault::pki::gen_cert resource.
#     'alt_names'             => 'Subject Alternative Names, comma separated'
#     'country'               => 'US',
#     'exclude_cn_from_sans'  => (bool),
#     'ip_sans'               => (slice),
#     'key_bits'              => '256',
#     'key_type'              => 'ec',
#     'locality'              => (slice),
#     'max_path_length'       => (int),
#     'organization'          => 'Encore Technologies',
#     'other_sans'            => (slice),
#     'ou'                    => (slice),
#     'permitted_dns_domains' => (slice),
#     'postal_code'           => (slice),
#     'province'              => (slice),
#     'serial_number'         => (string),
#     'street_address'        => (slice),
#     'uri_sans'              => (slice),
#
class vault (
  Optional[String]           $api_addr                  = $vault::params::api_addr,
  String                     $arch                      = $vault::params::arch,
  String                     $bin_dir                   = $vault::params::bin_dir,
  String                     $config_dir                = '/etc/vault',
  String                     $config_mode               = '0750',
  Optional[String]           $default_lease_ttl         = $vault::params::default_lease_ttl,
  Optional[Boolean]          $disable_cache             = $vault::params::disable_cache,
  Optional[Boolean]          $disable_mlock             = $vault::params::disable_mlock,
  String                     $domain                    = $facts['networking']['domain'],
  String                     $download_dir              = '/tmp',
  String                     $download_extension        = 'zip',
  String                     $download_filename         = 'vault.zip',
  String                     $download_url_base         = 'https://releases.hashicorp.com/vault/',
  Optional[String]           $download_url              = undef,
  Boolean                    $enable_int_ca             = false,
  Boolean                    $enable_ldap               = false,
  Boolean                    $enable_root_ca            = false,
  Boolean                    $enable_ui                 = true,
  Optional[Hash]             $extra_config              = undef,
  String                     $group                     = 'vault',
  Optional[Hash]             $ha_storage                = $vault::params::ha_storage,
  Optional[Boolean]          $initialize_vault          = undef,
  String                     $install_dir               = '/opt/vault',
  String                     $install_method            = $vault::params::install_method,
  Optional[Hash]             $int_ca_config             = undef,
  String                     $ip_address                = $facts['networking']['ip'],
  Optional[Hash]             $ldap_config               = undef,
  Optional[Hash]             $ldap_groups               = undef,
  Variant[Hash,Array[Hash]]  $listener                  = $vault::params::listener,
  Boolean                    $manage_download_dir       = false,
  Optional[Boolean]          $manage_file_capabilities  = $vault::params::manage_file_capabilities,
  Boolean                    $manage_group              = true,
  Optional[Boolean]          $manage_service_file       = $vault::params::manage_service_file,
  Boolean                    $manage_service            = true,
  Boolean                    $manage_storage_dir        = $vault::params::manage_storage_dir,
  Boolean                    $manage_user               = true,
  Optional[String]           $max_lease_ttl             = $vault::params::max_lease_ttl,
  Integer                    $min_keys                  = 2,
  Integer                    $num_procs                 = $vault::params::num_procs,
  String                     $os                        = $vault::params::os,
  Enum['present','installed','absent','purged','latest'] $package_ensure = 'installed',
  String                     $package_name              = 'vault',
  String                     $port                      = $vault::params::vault_port,
  Optional[String]           $published_url             = undef,
  Boolean                    $purge_config_dir          = true,
  Optional[Hash]             $root_ca_config            = undef,
  Optional[Hash]             $seal                      = $vault::params::seal,
  Boolean                    $service_enable            = true,
  Enum['stopped','running']  $service_ensure            = 'running',
  String                     $service_name              = 'vault',
  Optional[String]           $service_options           = undef,
  String                     $service_provider          = $vault::params::service_provider,
  Optional[Hash]             $storage                   = $vault::params::storage,
  Optional[Hash]             $telemetry                 = $vault::params::telemetry,
  Optional[String]           $token                     = undef,
  Integer                    $total_keys                = 5,
  String                     $user                      = 'vault',
  Optional[Array[String]]    $vault_keys                = undef,
  Optional[Hash]             $vault_policies            = $vault::params::default_policies,
  String                     $version                   = '1.3.2',
  Boolean                    $manage_vault_utils        = true,
) inherits vault::params {
  #
  $_download_url     = "${download_url_base}${version}"
  $_download_file    = "${package_name}_${version}_${os}_${arch}.${download_extension}"
  $real_download_url = pick($download_url, "${_download_url}/${_download_file}")
  $vault_address     = "http://${ip_address}:${port}"
  $_vault_utils      = ['openssl','jq']

  if $manage_vault_utils {
    package { $_vault_utils: ensure => present }
  }

  contain vault::install
  contain vault::config
  contain vault::service

  Class['vault::install']
  -> Class['vault::config']
  ~> Class['vault::service']

  # initialize vault
  if $initialize_vault or ($initialize_vault == undef and !$facts['vault_initialized']) {
    contain vault::config::initialize
    Class['vault::service']
    -> Class['vault::config::initialize']
  }

  ## Setup ldap authentication for vault
  if $enable_ldap {
    create_resources ('vault::config::ldap', $ldap_config)
  }

  ## Setup root CA PKI infrastructure
  if $enable_root_ca {
    create_resources ('vault::pki::root_ca', $root_ca_config)
  }

  ## Setup intermediate CA PKI infrastrucutre
  if $enable_int_ca {
    create_resources ('vault::pki::int_ca', $int_ca_config)
  }

  ## Configure vault user policies
  create_resources ('vault::config::policy', $vault_policies)
}
