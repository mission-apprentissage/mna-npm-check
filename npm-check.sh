#!/usr/bin/env bash

set -eo pipefail

readonly P_NAME=$(basename $0)
readonly P_DIR=$(readlink -f $(dirname $0))
readonly P_ARGS="${@}"
readonly P_USER="$LOGNAME"
readonly P_HOME=$(bash -c "cd ~$(printf %q "$P_USER") && pwd")

usage() {

  cat <<- EOF

  usage: $P_NAME

  Script to analyze traces of the Shai-Hulud attack on the NPM supply chain

  OPTIONS:
    -h
      show this help
    -p
      project to analyse
    -f
      file to analyze

EOF

}

log() {
  local TIMESTAMP=`date "+%Y-%m-%d %H:%M:%S"`
  echo -e "$TIMESTAMP | $1"
}

eexit() {
  log "$1" 1>&2
  exit 1
}

cleanup() {
  if [ -d "$TEMP_DIR" ]; then

    if ! rm -fr "$TEMP_DIR"; then
      eexit "Error: Failed to release temporary directory '$TEMP_DIR'"
    else
      log "Temporary directory released $TEMP_DIR"
      log "Finished."
    fi

  fi

}

abort() {
  echo
  exit 1
}

download_compromised_packages_list() {

  local readonly compromised_packages_url="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/672c7afd14c1748cb0328cd84f9a798cc401b899/compromised-packages.txt"

  if ! command -v curl &> /dev/null; then
    eexit "Error: curl is missing !"
  fi

  log "Downloading affected packages list..."

  if ! curl -s "$compromised_packages_url" -o "$COMPROMISED_PACKAGES_FILE" 2>/dev/null; then
    eexit "Error: Unable to download the compromised packages list!"
  fi

}

count_files() {
  (find "$@" 2>/dev/null || true) | wc -l | tr -d ' '
}

#
# Convert pnpm-lock.yaml to pseudo-package-lock.json format for parsing
#
transform_pnpm_yaml() {

  declare -a path
  packages_file=$1

  echo -e "{"
  echo -e "  \"packages\": {"

  depth=0
  while IFS= read -r line; do

    # Find indentation
    sep="${line%%[^ ]*}"
    currentdepth="${#sep}"

    # Remove surrounding whitespace
    line=${line##*( )} # From the beginning
    line=${line%%*( )} # From the end

    # Remove comments
    line=${line%%#*}
    line=${line%%*( )}

    # Remove comments and empty lines
    if [[ "${line:0:1}" == '#' ]] || [[ "${#line}" == 0 ]]; then
      continue
    fi

    # split into key/val
    key=${line%%:*}
    key=${key%%*( )}
    val=${line#*:}
    val=${val##*( )}

    # Save current path
    path[$currentdepth]=$key

    # Interested in packages.*
    if [ "${path[0]}" != "packages" ]; then continue; fi
    if [ "${currentdepth}" != "2" ]; then continue; fi

    # Remove surrounding whitespace (yes, again)
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"

    # Remove quote
    key="${key#"${key%%[!\']*}"}"
    key="${key%"${key##*[!\']}"}"

    # split into name/version
    name=${key%\@*}
    name=${name%*( )}
    version=${key##*@}
    version=${version##*( )}

    echo "  \"${name}\": {"
    echo "    \"version\": \"${version}\""
    echo "  },"

  done < "$packages_file"

  echo "  }"
  echo "}"

}

#
# Parse semantic version string into major, minor, patch, and special components
#
semverParseInto() {
  local re='[^0-9]*\([0-9]*\)[.]\([0-9]*\)[.]\([0-9]*\)\([0-9A-Za-z-]*\)'
  #MAJOR
  printf -v "$2" '%s' "$(echo $1 | sed -e "s/$re/\1/")"
  #MINOR
  printf -v "$3" '%s' "$(echo $1 | sed -e "s/$re/\2/")"
  #PATCH
  printf -v "$4" '%s' "$(echo $1 | sed -e "s/$re/\3/")"
  #SPECIAL
  printf -v "$5" '%s' "$(echo $1 | sed -e "s/$re/\4/")"
}

#
# Check if version matches semver pattern with caret (^), tilde (~), or exact matching
#
semver_match() {
  local test_subject=$1
  local test_pattern=$2

  # Always matches
  if [[ "*" == "${test_pattern}" ]]; then
    return 0
  fi

  # Destructure subject
  local subject_major=0
  local subject_minor=0
  local subject_patch=0
  local subject_special=0
  semverParseInto ${test_subject} subject_major subject_minor subject_patch subject_special

  # Handle multi-variant patterns
  while IFS= read -r pattern; do
    pattern="${pattern#"${pattern%%[![:space:]]*}"}"
    pattern="${pattern%"${pattern##*[![:space:]]}"}"
    # Always matches
    if [[ "*" == "${pattern}" ]]; then
      return 0
    fi
    local pattern_major=0
    local pattern_minor=0
    local pattern_patch=0
    local pattern_special=0
    case "${pattern}" in
      ^*) # Major must match
        semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
        [[ "${subject_major}"  ==  "${pattern_major}"   ]] || continue
        [[ "${subject_minor}" -ge  "${pattern_minor}"   ]] || continue
        if [[ "${subject_minor}" == "${pattern_minor}"   ]]; then
          [[ "${subject_patch}"   -ge "${pattern_patch}"   ]] || continue
        fi
        return 0 # Match
        ;;
      ~*) # Major+minor must match
        semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
        [[ "${subject_major}"   ==  "${pattern_major}"   ]] || continue
        [[ "${subject_minor}"   ==  "${pattern_minor}"   ]] || continue
        [[ "${subject_patch}"   -ge "${pattern_patch}"   ]] || continue
        return 0 # Match
        ;;
      *[xX]*) # Wildcard pattern (4.x, 1.2.x, 4.X, 1.2.X, etc.)
        # Parse pattern components, handling 'x' wildcards specially
        local pattern_parts
        IFS='.' read -ra pattern_parts <<< "${pattern}"
        local subject_parts
        IFS='.' read -ra subject_parts <<< "${test_subject}"

        # Check each component, skip comparison for 'x' wildcards
        for i in 0 1 2; do
          if [[ ${i} -lt ${#pattern_parts[@]} && ${i} -lt ${#subject_parts[@]} ]]; then
            local pattern_part="${pattern_parts[i]}"
            local subject_part="${subject_parts[i]}"

            # Skip wildcard components (both lowercase x and uppercase X)
            if [[ "${pattern_part}" == "x" ]] || [[ "${pattern_part}" == "X" ]]; then
              continue
            fi

            # Extract numeric part (remove any non-numeric suffix)
            pattern_part=$(echo "${pattern_part}" | sed 's/[^0-9].*//')
            subject_part=$(echo "${subject_part}" | sed 's/[^0-9].*//')

            # Compare numeric parts
            if [[ "${subject_part}" != "${pattern_part}" ]]; then
              continue 2  # Continue outer loop (try next pattern)
            fi
          fi
        done
        return 0 # Match
        ;;
      *) # Exact match
        semverParseInto ${pattern} pattern_major pattern_minor pattern_patch pattern_special
        [[ "${subject_major}"  -eq "${pattern_major}"   ]] || continue
        [[ "${subject_minor}"  -eq "${pattern_minor}"   ]] || continue
        [[ "${subject_patch}"  -eq "${pattern_patch}"   ]] || continue
        [[ "${subject_special}" == "${pattern_special}" ]] || continue
        return 0 # MATCH
        ;;
    esac
    # Splits '||' into newlines with sed
  done < <(echo "${test_pattern}" | sed 's/||/\n/g')

  # Fallthrough = no match
  return 1;
}

#
# Extract actual installed version from lockfile for a specific package
#
get_lockfile_version() {
  local package_name="$1"
  local package_dir="$2"
  local scan_boundary="$3"

  # Search upward for lockfiles (supports packages in node_modules subdirectories)
  local current_dir="$package_dir"

  # Traverse up the directory tree until we find a lockfile, reach root, or hit scan boundary
  while [[ "$current_dir" != "/" && "$current_dir" != "." && -n "$current_dir" ]]; do
    # SECURITY: Don't search above the original scan directory boundary
    if [[ ! "$current_dir/" =~ ^"$scan_boundary"/ && "$current_dir" != "$scan_boundary" ]]; then
      break
    fi
    # Check for package-lock.json first (most common)
    if [[ -f "$current_dir/package-lock.json" ]]; then

      # Use the existing logic from check_package_integrity for block-based parsing
      local found_version
      found_version=$(awk -v pkg="node_modules/$package_name" '
        $0 ~ "\"" pkg "\":" { in_block=1; brace_count=1 }
        in_block && /\{/ && !($0 ~ "\"" pkg "\":") { brace_count++ }
        in_block && /\}/ {
          brace_count--
          if (brace_count <= 0) { in_block=0 }
        }
        in_block && /\s*"version":/ {
          # Extract version value between quotes
          split($0, parts, "\"")
          for (i in parts) {
            if (parts[i] ~ /^[0-9]/) {
              print parts[i]
              exit
            }
          }
        }
      ' "$current_dir/package-lock.json" 2>/dev/null || true)

      if [[ -n "$found_version" ]]; then
        echo "$found_version"
        return
      fi
    fi

    # Check for yarn.lock
    if [[ -f "$current_dir/yarn.lock" ]]; then

      # Yarn.lock format: package-name@version:
      local found_version
      found_version=$(grep "^\"\\?$package_name@" "$current_dir/yarn.lock" 2>/dev/null | head -1 | sed 's/.*@\([^"]*\).*/\1/' 2>/dev/null || true)
      if [[ -n "$found_version" ]]; then
        echo "$found_version"
        return
      fi
    fi

    # Check for pnpm-lock.yaml
    if [[ -f "$current_dir/pnpm-lock.yaml" ]]; then

      # Use transform_pnpm_yaml and then parse like package-lock.json
      local temp_lockfile
      temp_lockfile=$(mktemp "${TMPDIR:-/tmp}/pnpm-parse.XXXXXXXX")
      TEMP_FILES+=("$temp_lockfile")

      transform_pnpm_yaml "$current_dir/pnpm-lock.yaml" > "$temp_lockfile" 2>/dev/null

      local found_version
      found_version=$(awk -v pkg="$package_name" '
        $0 ~ "\"" pkg "\"" { in_block=1; brace_count=1 }
        in_block && /\{/ && !($0 ~ "\"" pkg "\"") { brace_count++ }
        in_block && /\}/ {
          brace_count--
          if (brace_count <= 0) { in_block=0 }
        }
        in_block && /\s*"version":/ {
          gsub(/.*"version":\s*"/, "")
          gsub(/".*/, "")
          print $0
          exit
        }
      ' "$temp_lockfile" 2>/dev/null || true)

      if [[ -n "$found_version" ]]; then
        echo "$found_version"
        return
      fi
    fi

    # Move to parent directory
    current_dir=$(dirname "$current_dir")
  done

  # No lockfile or package not found
  echo ""
}

#
# Load compromised package database from external file or fallback list
#
load_compromised_packages() {

    COMPROMISED_PACKAGES=()

    log "Loading compromised packages from $COMPROMISED_PACKAGES_FILE"

    if [ -f "$COMPROMISED_PACKAGES_FILE" ]; then

      while IFS= read -r line; do

        line="${line%$'\r'}"

        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        [[ -z "${line// }" ]] && continue

        if [[ "$line" =~ ^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            COMPROMISED_PACKAGES+=("$line")
        fi

      done < "$COMPROMISED_PACKAGES_FILE"

      log "Loaded ${#COMPROMISED_PACKAGES[@]} compromised packages"

    fi

}

check_package() {

  local package_file="$1"

  log "Analysing file $package_file" 

  while IFS=: read -r package_name package_version; do

    package_version=$(echo "${package_version}" | cut -d'"' -f2)
    package_name=$(echo "${package_name}" | cut -d'"' -f2)

    for malicious_info in "${COMPROMISED_PACKAGES[@]}"; do

      local malicious_name="${malicious_info%:*}"
      local malicious_version="${malicious_info#*:}"

      [[ "${package_name}" == "${malicious_name}" ]] || continue

      if [[ "${package_version}" == "${malicious_version}" ]]; then
        # Exact match, certainly compromised
        echo "$package_file:$package_name@$package_version" >> "$TEMP_DIR/compromised-found.txt"
      elif semver_match "${malicious_version}" "${package_version}"; then
        # Semver pattern match - check lockfile for actual installed version
        local package_dir
        package_dir=$(dirname "$package_file")
        local actual_version
        actual_version=$(get_lockfile_version "$package_name" "$package_dir" "$scan_dir")

        if [[ -n "$actual_version" ]]; then
          # Found actual version in lockfile
          if [[ "$actual_version" == "$malicious_version" ]]; then
            # Actual installed version is compromised
            echo "$package_file:$package_name@$actual_version" >> "$TEMP_DIR/compromised-found.txt"
          else
            # Lockfile has safe version but package.json range could update to compromised
            echo "$package_file:$package_name@$package_version (locked to $actual_version - safe)" >> "$TEMP_DIR/lockfile-safe-versions.txt"
          fi
        else
          # No lockfile or package not found - potential risk on install/update
          echo "$package_file:$package_name@$package_version" >> "$TEMP_DIR/suspicious-found.txt"
        fi
      fi

    done

  done < <(awk '/"dependencies":|"devDependencies":/{flag=1;next}/}/{flag=0}flag' "${package_file}")

}


#
# Find and scan package.json files for compromised packages
#
check_project() {

  local scan_dir=$1
  local filesCount=$(count_files "$scan_dir" -name "package.json")
  filesCount=$((filesCount))

  while IFS= read -r -d '' package_file; do

    if [ ! -r "$package_file" ]; then
      continue
    fi

    check_package "$package_file"

  done < <(find "$scan_dir" -name "package.json" -type f ! -path "*/node_modules/*" -print0 2>/dev/null || true)

} 

#
# Generate comprehensive security report with risk stratification and findings
#
generate_report() {

  local high_risk=0
  local medium_risk=0
  local total_issues=0

  if [[ -s "$TEMP_DIR/compromised-found.txt" ]]; then

    log "HIGH RISK: Compromised package versions detected:"
    echo

    while IFS= read -r entry; do

      local file_path="${entry%:*}"
      local package_info="${entry#*:}"
      echo "   - Package: $package_info"
      echo "     Found in: $file_path"
      high_risk=$((high_risk+1))

    done < "$TEMP_DIR/compromised-found.txt"

    echo
    echo -e "   NOTE: These specific package versions are known to be compromised."
    echo -e "   You should immediately update or remove these packages."
    echo

  fi

  if [ -s "$TEMP_DIR/suspicious-found.txt" ]; then

    log "MEDIUM RISK: Suspicious package versions detected:"
    echo

    while IFS= read -r entry; do

      local file_path="${entry%:*}"
      local package_info="${entry#*:}"
      echo "   - Package: $package_info"
      echo "     Found in: $file_path"
      medium_risk=$((medium_risk+1))

    done < "$TEMP_DIR/suspicious-found.txt"

    echo
    echo -e "   NOTE: Manual review required to determine if these are malicious."
    echo

  fi

  if [ -s "$TEMP_DIR/lockfile-safe-versions.txt" ]; then

    log "LOW RISK: Packages with safe lockfile versions:"
    echo

    while IFS= read -r entry; do

      local file_path="${entry%:*}"
      local package_info="${entry#*:}"
      echo "   - Package: $package_info"
      echo "     Found in: $file_path"

    done < "$TEMP_DIR/lockfile-safe-versions.txt"

    echo
    echo -e "   NOTE: These package.json ranges could match compromised versions, but lockfiles pin to safe versions."
    echo -e "   Your current installation is safe. Avoid running 'npm update' without reviewing changes."
    echo

  fi

  total_issues=$((high_risk + medium_risk))

  log "Total Critical Issues: $total_issues"
  log " \`- High Risk Issues: $high_risk"
  log " \`- Medium Risk Issues: $medium_risk"

  if [ $total_issues -eq 0 ]; then
    log "No indicators of Shai-Hulud compromise detected."
    log "Your system appears clean from this specific attack."
  else
    eexit "Indicators of Shai-Hulud compromise detected!"
  fi
}

main() {

  while getopts "hf:p:" opt; do
    case "$opt" in
      "h") usage; exit 0 ;;
      "f") local readonly FILE=$OPTARG ;;
      "p") local readonly PROJECT=$OPTARG ;;
      "?") usage >&2; exit 1 ;;
    esac
  done

  local readonly start_time=$(date +%s)

  trap "abort" INT QUIT TERM
  trap "cleanup" EXIT

  if [ -z "$FILE" ] && [ -z "$PROJECT" ]; then
    eexit "Error: File or folder option is mandatory"
  fi

  if [ ! -z "$PROJECT" ] && [ ! -d "$PROJECT" ]; then
    eexit "Error: File $PROJECT doesn't exist !"
  fi

  if [ ! -z "$FILE" ] && [ ! -f "$FILE" ]; then
    eexit "Error: File $FILE doesn't exist !"
  fi

  readonly TEMP_DIR=$(mktemp -d)
  readonly COMPROMISED_PACKAGES_FILE="$TEMP_DIR/compromised-packages.json"

  log "Temporary directory $TEMP_DIR created"

  local readonly download_start=$(date +%s)

  download_compromised_packages_list
  load_compromised_packages

  local readonly download_end=$(date +%s)
  local readonly download_time=$((download_end - download_start))

  local readonly check_packages_start=$(date +%s)

  if [ ! -z "$PROJECT" ]; then
    check_project "$PROJECT"
  elif [ ! -z "$FILE" ]; then
    check_package "$FILE"
  fi

  local readonly check_packages_end=$(date +%s)
  local readonly check_packages_time=$((check_packages_end - check_packages_start))

  local readonly end_time=$(date +%s)
  local readonly total_time=$((end_time - start_time))

  log "Temps d'exécution total: ${total_time}s"
  log " \`- Téléchargement: ${download_time}s"
  log " \`- Analyse: ${check_packages_time}s"

  generate_report

}

main $P_ARGS
