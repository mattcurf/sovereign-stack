"""Fail closed when conversion or rescanning loses identified packages."""


def native_package_ids(document):
    if not isinstance(document, dict) or document.get('SchemaVersion') != 2:
        raise ValueError('Expected native Trivy schema 2')
    results = document.get('Results', [])
    if not isinstance(results, list):
        raise ValueError('Malformed Trivy Results')
    identities = set()
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get('Packages', []), list):
            raise ValueError('Malformed Trivy package result')
        for package in result.get('Packages', []):
            if not isinstance(package, dict):
                raise ValueError('Malformed Trivy package')
            identifier = package.get('Identifier', {})
            if not isinstance(identifier, dict):
                raise ValueError('Malformed Trivy package identifier')
            purl = identifier.get('PURL')
            if purl is None:
                # Cargo graph placeholders have only an ID, not an identified package.
                if package.get('Name') and package.get('Version'):
                    raise ValueError('Identified native package is missing PURL')
                continue
            if not isinstance(purl, str) or not purl.startswith('pkg:'):
                raise ValueError('Malformed native PURL')
            identities.add(purl)
    return identities


def source_identity(package):
    name, version = package.get('SrcName'), package.get('SrcVersion')
    release = package.get('SrcRelease', '')
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ValueError('Missing Debian source package identity')
    if not isinstance(release, str):
        raise ValueError('Malformed Debian source release')
    epoch = int(package.get('SrcEpoch', 0))
    return name, f'{epoch}:{version}' + (f'-{release}' if release else '')


def native_os_context(document):
    packages = {}
    for result in document.get('Results', []):
        if result.get('Class') != 'os-pkgs':
            continue
        for package in result.get('Packages', []):
            if result.get('Type') != 'debian':
                raise ValueError('Unexpected OS package type for this Debian stack')
            packages[package['Identifier']['PURL']] = source_identity(package)
    if not packages:
        return None
    os = document['Metadata']['OS']
    if os.get('Family') != 'debian' or not isinstance(os.get('Name'), str) or not os['Name']:
        raise ValueError('Missing Debian release identity')
    return (os['Family'], os['Name']), packages


def validate_inventory(sbom, native, report=None):
    if not isinstance(sbom, dict) or sbom.get('bomFormat') != 'CycloneDX':
        raise ValueError('Expected CycloneDX inventory')
    components = sbom.get('components')
    metadata = sbom.get('metadata', {})
    if not isinstance(components, list) or not isinstance(metadata, dict):
        raise ValueError('Missing CycloneDX components or metadata')
    root = metadata.get('component', {})
    if (not isinstance(root, dict) or not root.get('name') or not root.get('bom-ref')
            or {'name': 'aquasecurity:trivy:SchemaVersion', 'value': '2'}
            not in root.get('properties', [])):
        raise ValueError('Missing Trivy CycloneDX root metadata')
    producers = metadata.get('tools', {}).get('components', [])
    if not any(tool.get('name') == 'trivy' and tool.get('group') == 'aquasecurity'
               for tool in producers):
        raise ValueError('Expected Trivy-generated CycloneDX')
    identities = set()
    for component in components:
        if (not isinstance(component, dict) or not component.get('name')
                or not component.get('bom-ref')):
            raise ValueError('Malformed CycloneDX component')
        kind = component.get('type')
        if kind == 'library':
            purl = component.get('purl')
            if not isinstance(purl, str) or not purl.startswith('pkg:'):
                raise ValueError('CycloneDX library is missing PURL')
            identities.add(purl)
        elif kind not in ('application', 'operating-system'):
            raise ValueError('Unexpected Trivy CycloneDX component type')
    if identities != native_package_ids(native):
        raise ValueError('CycloneDX package inventory differs from native inventory')
    if report is not None and identities != native_package_ids(report):
        raise ValueError('Rescan lost or changed identified packages')
    context = native_os_context(native)
    if context is not None:
        os_identity, packages = context
        operating_systems = [(c['name'], c.get('version')) for c in components
                             if c['type'] == 'operating-system']
        if operating_systems != [os_identity]:
            raise ValueError('CycloneDX changed or lost OS release')
        converted = {}
        for component in components:
            if component.get('purl') not in packages:
                continue
            properties = {}
            for prop in component.get('properties', []):
                key = prop['name'].removeprefix('aquasecurity:trivy:')
                if key in properties:
                    raise ValueError('Duplicate CycloneDX package property')
                properties[key] = prop['value']
            if properties.get('PkgType') != 'debian':
                raise ValueError('CycloneDX changed or lost Debian package type')
            converted[component['purl']] = source_identity(properties)
        if converted != packages:
            raise ValueError('CycloneDX changed Debian source package identity')
        if report is not None and native_os_context(report) != context:
            raise ValueError('Rescan changed OS or Debian source package identity')
