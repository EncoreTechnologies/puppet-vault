# @summary define class to create and configure root certificate of authority
#
# @api private
#
define vault::pki::int_ca (
  Optional[Hash]      $cert_options          = undef,
  String              $common_name           = undef,
  Boolean             $enable_root_ca        = $vault::enable_root_ca,
  Optional[Hash]      $options               = undef,
  String              $path                  = undef,
  Optional[String]    $published_url         = undef,
  Optional[String]    $role_name             = undef,
  Optional[Hash]      $role_options          = undef,
  String              $root_path             = 'root_ca',
  Boolean             $sign_intermediate     = true,
  String              $ttl                   = '8760h',
  String              $vault_addr            = $vault::vault_address,
  String              $vault_dir             = $vault::install_dir,
) {
  $cert_csr    = "${vault_dir}/certs/${path}.csr"
  $cert        = "${vault_dir}/certs/${path}.crt"
  $root_cert   = "${vault_dir}/certs/${root_path}.crt"
  $_safe_name  = regsubst($common_name, ' ', '_', 'G')

  ## Initialize pki secrets engine
  vault::secrets::engine { $path:
    engine  => 'pki',
    options => {
      'max-lease-ttl' => $ttl,
    },
  }

  ## Generate intermediate csr and private key
  vault::pki::generate_cert { $path:
    common_name  => $common_name,
    pkey_mode    => 'exported',
    cert_options => $cert_options,
    ttl          => $ttl,
    is_int_ca    => true,
  }

  ## Sign the intermediate CA with root if true and root CA enabled.
  if $sign_intermediate and $enable_root_ca {
    $_sign_int_ca_cmd = @("EOC")
      bash -lc "${vault::bin_dir}/vault write -format=json ${root_path}/root/sign-intermediate \
        csr=@${cert_csr} format=pem_bundle ttl='${ttl}' |\
        jq -r '.data.certificate' > ${cert}"
      | EOC

    ## Sign the intermediate CA CSR
    exec { 'sign_cert':
      command  => $_sign_int_ca_cmd,
      path     => [$vault::bin_dir,'/bin','/usr/bin'],
      #refreshonly => true,
      creates  => $cert,
      provider => 'shell',
      notify   => [
        Exec['import_cert'],
        Exec['append_root_ca'],
      ],
      require  => Vault::Pki::Generate_cert[$path],
    }

    ## Append Root CA to intermediate CA.
    exec { 'append_root_ca':
      command     => "cat ${root_cert} >> ${cert}",
      path        => ['/bin','/usr/bin'],
      refreshonly => true,
      provider    => 'shell',
    }

    ## Import signed intermediate CA certificate
    $_import_int_ca_cert = @("EOC")
      bash -lc "${vault::bin_dir}/vault write ${path}/intermediate/set-signed certificate=@${cert}"
      | EOC

    exec { 'import_cert':
      command     => $_import_int_ca_cert,
      path        => [$vault::bin_dir,'/bin','/usr/bin'],
      refreshonly => true,
      provider    => 'shell',
      require     => Vault::Pki::Generate_cert[$path],
    }
  }

  ## Configure intermediate CA urls
  $_published_url = pick($published_url, $vault_addr)
  vault::pki::config { $path:
    action  => 'write',
    path    => "${path}/config/urls",
    options => {
      'issuing_certificates'    => "${_published_url}/v1/${path}/ca/pem",
      'crl_distribution_points' => "${_published_url}/v1/${path}/crl/pem",
      #'ocsp_servers'           => (slice),
    },
  }

  ## Configure role for intermediate CA
  if $role_name != undef {
    vault::pki::config { "${path}_role":
      action  => 'write',
      path    => "${path}/roles/${role_name}",
      options => $role_options,
    }
  }
}
