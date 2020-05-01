# == (Private) Class to create and configure root certificate of authority
define vault::pki::int_ca (
  Optional[Hash]      $cert_options          = undef,
  String              $common_name           = undef,
  Boolean             $enable_root_ca        = $vault::enable_root_ca,
  Optional[Hash]      $options               = undef,
  String              $path                  = undef,
  Optional[String]    $role_name             = undef,
  Optional[Hash]      $role_options          = undef,
  Optional[String]    $root_path             = 'root_ca',
  Optional[Boolean]   $sign_intermediate     = true,
  Optional[String]    $ttl                   = '8760h',
  String              $vault_addr            = $vault::vault_address,
  String              $vault_dir             = $vault::install_dir,
) {

  $cert_csr    = "${vault_dir}/certs/${path}.csr"
  $cert        = "${vault_dir}/certs/${path}.cert"
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
      vault write -format=json ${root_path}/root/sign-intermediate \
        csr=@${cert_csr} format=pem_bundle ttl='${ttl}' |\
        jq -r '.data.certificate' > ${cert}
      | EOC

      #    ## Idempontent check.
      #    file { "${vault_dir}/scripts/.sign_cert_${_safe_name}.cmd":
      #      ensure  => present,
      #      content => $_sign_int_ca_cmd,
      #      mode    => '0640',
      #      notify  => Exec['sign_cert'],
      #      require => [
      #        "Vault::Pki::Generate_cert[$root_path]",
      #        "Vault::Pki::Config[$root_path]",
      #        "Vault::Pki::Config[${root_path}_role]",
      #      ],
      #    }
 
    ## Sign the intermediate CA CSR
    exec { 'sign_cert':
      command => $_sign_int_ca_cmd,
      path    => [ $vault::bin_dir, '/bin', '/usr/bin' ],
      #refreshonly => true,
      creates => $cert,
      notify  => Exec['import_cert'],
      require => Vault::Pki::Generate_cert[$path],
    }

    ## Import signed intermediate CA certificate
    $_import_int_ca_cert = "vault write ${path}/intermediate/set-signed certificate=@${cert}"

    exec { 'import_cert':
      command     => $_import_int_ca_cert,
      path        => [ $vault::bin_dir, '/bin', '/usr/bin' ],
      refreshonly => true,
      require     => Vault::Pki::Generate_cert[$path],
    }
  }

  ## Configure intermediate CA urls
  vault::pki::config { $path:
    action  => 'write',
    path    => "${path}/config/urls",
    options => {
      'issuing_certificates'    => "http://${vault_addr}/v1/${path}/ca/pem",
      'crl_distribution_points' => "http://${vault_addr}/v1/${path}/crl/pem",
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