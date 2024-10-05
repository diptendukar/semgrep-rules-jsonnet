local lib = import 'lib.libsonnet';
local mavenrule = import 'lib/core/ssc-templates/mavenrule.libsonnet';

local rules = lib.utils.shortcuts.rules;
local Pattern = lib.utils.patterns.Pattern;

rules([
  mavenrule(
    id='ssc-23b5a522-77ee-4c77-8f74-59ff952267a0',
    ghsa_id='GHSA-1111-2222-3333',
    scakind='reachable',
    override_message='Affected versions of org.apache.axis:axis are vulnerable to Improper Input Validation. The use of `ServiceFactory.getService` enables the lookup of sensitive mechanisms, such as LDAP, for service identification. If untrusted input is supplied to this API method, the application may become vulnerable to various threats, including DoS, SSRF, and RCE',
    extra_cwes=['CWE-20: Improper Input Validation'],
  ) {

  },
])