// Alpine cloud images can predate Python subpackage splits in the same
// distribution branch. Align only the installed Python group before adding
// SSH dependencies; never force file overwrites or change world constraints.
export const alpinePythonPackagePreparation = `prepare_alpine_python_packages() {
  set --
  for package in python3 python3-ndbm pyc python3-pyc python3-pycache-pyc0; do
    if apk info -e "$package" >/dev/null 2>&1; then set -- "$@" "$package"; fi
  done
  [ "$#" -gt 0 ] || return 0
  if apk --timeout 20 --wait 5 upgrade "$@"; then return 0; fi
  # An interrupted earlier add may leave the newly split package incomplete.
  # Re-read the installed group and repair it after the Python revision aligns.
  set --
  for package in python3 python3-ndbm pyc python3-pyc python3-pycache-pyc0; do
    if apk info -e "$package" >/dev/null 2>&1; then set -- "$@" "$package"; fi
  done
  [ "$#" -gt 0 ] || return 1
  apk --timeout 20 --wait 5 fix "$@"
}`
