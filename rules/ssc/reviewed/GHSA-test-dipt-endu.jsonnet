local lib = import 'lib.libsonnet';
local csharprule = import 'lib/core/ssc-templates/csharprule.libsonnet';
local rules = lib.utils.shortcuts.rules;
rules([
  csharprule(
    id='ssc-5f6cabde-3469-4659-b1ba-21a4659daab7',
    ghsa_id='GHSA-test-dipt-endu',
    scakind='upgrade-only',
    message='Caused by CVE-2023-4863 - heap overflow in WebP.',
    // reachable_if='optional, will create an `sca-reachable-if` metadata field',
    extra_cwes=['CWE-122: Heap-based Buffer Overflow'],
    // languages=['optional list of languages, defaults to the default language set for this rule']
  ) {
  },
])
