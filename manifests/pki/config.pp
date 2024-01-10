# @summary Define to configure pki path
#
# @api private
#
define vault::pki::config (
  String[1]             $action           = undef,
  Optional[Hash]        $options          = undef,
  String[1]             $path             = undef,
) {
  ## Unseal vault if needed
  contain vault::config::unseal

  ## Parse options if defined
  if $options != undef {
    $_options = join($options.map |$key, $value| { "${key}='${value}'" }, ' ')
  }

  $_config_cmd = @("EOC")
    bash -lc "${vault::bin_dir}/vault ${action} ${path} ${_options}"
    | EOC

  ## Used for idempotencey
  $_file_name = regsubst($path, '/', '_', 'G')
  file { "${vault::install_dir}/scripts/.pki_config_${_file_name}.cmd":
    ensure  => file,
    content => $_config_cmd,
    mode    => '0640',
    notify  => Exec["${name}_cmd"],
  }

  exec { "${name}_cmd":
    command     => $_config_cmd,
    path        => [$vault::bin_dir, '/bin', '/usr/bin'],
    refreshonly => true,
    provider    => 'shell',
  }
}
