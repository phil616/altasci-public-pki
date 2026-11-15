#!/usr/bin/env python3
"""Check the maintained Console documentation against static source declarations.

No database, application secrets or network requests are needed. This is a drift
check for the current route/struct syntax, not a substitute for API integration
tests or reviewing validation rules, permissions and deployment procedures.
"""

from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

try:
    import yaml
    from openapi_spec_validator import validate
    from openapi_spec_validator.validation.exceptions import OpenAPIValidationError, ValidatorDetectError
except ImportError:
    sys.exit("Install scripts/requirements-docs.txt in a virtual environment first.")


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "doc/pki-console"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys rather than silently overwriting an operation."""


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError(f"Duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def resolve(document, value):
    seen = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        require(ref.startswith("#/"), f"Only local OpenAPI references are supported: {ref}")
        require(ref not in seen, f"Cyclic reference in declaration: {ref}")
        seen.add(ref)
        value = document
        for part in ref[2:].split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
    return value


def check_refs(document, node):
    if isinstance(node, dict):
        if "$ref" in node:
            resolve(document, node)
        for value in node.values():
            check_refs(document, value)
    elif isinstance(node, list):
        for value in node:
            check_refs(document, value)


def normalize_path(path):
    # Go registers {file}; the handler requires the suffix documented in OpenAPI.
    path = path.replace("/issuers/{slug}.cer", "/issuers/{file}")
    path = path.replace("/crl/{slug}.crl", "/crl/{file}")
    return re.sub(r"\{[^}]+\}", "{}", path)


def code_routes(source):
    routes = {}
    pattern = r's\.(console|public)\.Handle(?:Func)?\("(\w+) ([^" ]+)"([^\n]*)'
    declarations = re.findall(pattern, source)
    require(declarations, "No Go route declarations found; update the route extractor.")
    require(len(declarations) == len(re.findall(r's\.(?:console|public)\.Handle(?:Func)?\(', source)),
            "Unrecognized route declaration; update the route extractor.")
    for surface, method, path, middleware in declarations:
        key = (surface, method, normalize_path(path))
        require(key not in routes, f"Duplicate source route: {key}")
        routes[key] = middleware
    return routes


def check_routes(document, source):
    expected = code_routes(source)
    actual = {}
    operation_ids = set()
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method not in METHODS:
                continue
            operation_id = operation.get("operationId")
            require(operation_id and operation_id not in operation_ids,
                    f"Missing/duplicate operationId at {method} {path}")
            operation_ids.add(operation_id)
            parameters = [resolve(document, p) for p in
                          item.get("parameters", []) + operation.get("parameters", [])]
            parameter_names = {p["name"] for p in parameters if p["in"] == "path"}
            require(set(re.findall(r"\{([^}]+)\}", path)) == parameter_names,
                    f"Path parameter mismatch at {method} {path}")
            servers = operation.get("servers", item.get("servers", document["servers"]))
            for server in servers:
                server_url = server["url"]
                for name, variable in server.get("variables", {}).items():
                    server_url = server_url.replace("{" + name + "}", variable["default"])
                base = urlsplit(server_url)
                surface = {"pki-console.example.com": "console", "pki.example.com": "public"}.get(base.hostname)
                require(surface is not None, f"Unknown example server origin: {server_url}")
                key = (surface, method.upper(), normalize_path(base.path.rstrip("/") + path))
                require(key not in actual, f"Duplicate OpenAPI route: {key}")
                actual[key] = operation
                if key not in expected:
                    continue
                middleware = expected[key]
                authenticated = "s.requireAuth(" in middleware
                signing_bearer = "s.requireSigningToken(" in middleware
                security = operation.get("security", document.get("security", []))
                requirement = {"sessionCookie": []} if authenticated else None
                if authenticated and method not in {"get", "head"}:
                    requirement["csrfToken"] = []
                expected_security = [{"signingToken": []}] if signing_bearer else ([requirement] if requirement is not None else [])
                require(security == expected_security,
                        f"Session/CSRF declaration differs from middleware: {key}")
                idempotent = any(p["in"] == "header" and p["name"] == "Idempotency-Key"
                                 for p in parameters)
                require(idempotent == ("s.idempotent(" in middleware or "s.issueSigning)" in middleware),
                        f"Idempotency declaration differs from middleware: {key}")
                if idempotent:
                    header = next(p for p in parameters if p["in"] == "header" and p["name"] == "Idempotency-Key")
                    require(header.get("required", False) == ("s.issueSigning)" in middleware),
                            f"Idempotency required flag differs from handler: {key}")
                if signing_bearer:
                    match = re.search(r's\.requireSigningToken\("(issue|read|revoke)"', middleware)
                    require(match and operation.get("x-signing-scope") == match.group(1),
                            f"Signing scope differs from middleware: {key}")
    require(expected.keys() == actual.keys(),
            f"Route drift: missing={sorted(expected.keys() - actual.keys())}; "
            f"extra={sorted(actual.keys() - expected.keys())}")
    return len(actual)


def check_environment():
    source = (ROOT / "console/config/config.go").read_text()
    expected = set(re.findall(r'(?:os\.Getenv|getenv|envDefault)\("([A-Z][A-Z0-9_]+)"', source))
    example = set(re.findall(r"^([A-Z][A-Z0-9_]+)=", (ROOT / ".env.example").read_text(), re.M))
    table = set(re.findall(r"^\| `([A-Z][A-Z0-9_]+)` \|", (DOCS / "README.md").read_text(), re.M))
    require(expected and expected == example == table,
            f"Environment drift: code={sorted(expected)}, example={sorted(example)}, table={sorted(table)}")
    return len(expected)


def json_fields(source, declaration):
    match = re.search(declaration + r"\s*\{(.*?)^\s*\}", source, re.S | re.M)
    require(match is not None, f"Go struct not found: {declaration}")
    return {name for name in re.findall(r'json:"([^",]+)(?:,[^"]*)?"', match[1]) if name != "-"}


def check_fields(document):
    schemas = document["components"]["schemas"]
    count = 0

    def compare(file, declaration, schema, label):
        nonlocal count
        expected = json_fields((ROOT / file).read_text(), declaration)
        actual = set(resolve(document, schema).get("properties", {}))
        require(expected == actual,
                f"JSON field drift for {label}: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
        count += 1

    for schema, struct in {
        "User": "User", "CertificateAuthority": "CertificateAuthority", "CAGrant": "CAGrant",
        "SigningProfile": "SigningProfile", "TimestampAuthority": "TimestampAuthority",
        "CertificateRequest": "CertificateRequest", "CertificateSummary": "Certificate",
        "CertificateInventoryItem": "CertificateInventoryItem", "AuditRecord": "AuditRecord",
    }.items():
        compare("console/store/models.go", "type " + struct + " struct", schemas[schema], schema)
    for schema, file, struct in [
        ("SigningProfileInput", "console/httpapi/handlers_admin.go", "profileInput"),
        ("ImportCA", "console/pki/import.go", "ImportCAInput"),
        ("CreateCertificateRequest", "console/pki/service.go", "CreateRequestInput"),
        ("CreateTimestampAuthority", "console/tsa/service.go", "CreateAuthorityInput"),
    ]:
        compare(file, "type " + struct + " struct", schemas[schema], schema)
    for schema, struct in {
        "IndependentSigningPolicy": "Policy", "IndependentSigningPolicyInput": "Policy", "IndependentSigningInstance": "Instance",
        "IndependentSigningCredential": "Credential", "IndependentSigningCertificate": "Certificate",
        "IndependentSigningCreate": "CreateInput", "IndependentSigningUpdate": "UpdateInput",
        "IndependentSigningCredentialInput": "CredentialInput", "IndependentSigningIssue": "IssueInput",
        "IndependentSigningRevoke": "RevokeInput",
    }.items():
        compare("console/signing/models.go", "type " + struct + " struct", schemas[schema], schema)
    for file, handler, path, method in [
        ("handlers_auth.go", "login", "/auth/login", "post"),
        ("handlers_auth.go", "createUser", "/users", "post"),
        ("handlers_auth.go", "setUserStatus", "/users/{id}/status", "patch"),
        ("handlers_auth.go", "resetUserPassword", "/users/{id}/password", "put"),
        ("handlers_auth.go", "createGrant", "/cas/{id}/grants", "post"),
        ("handlers_pki.go", "exportCAKey", "/cas/{id}/keys/export", "post"),
        ("handlers_pki.go", "revokeCertificate", "/certificates/{id}/revoke", "post"),
        ("handlers_pki.go", "certInfo", "/utilities/certinfo", "post"),
        ("handlers_admin.go", "generateCSR", "/utilities/csr", "post"),
        ("handlers_admin.go", "bundleCertificates", "/utilities/bundle", "post"),
    ]:
        source = (ROOT / "console/httpapi" / file).read_text()
        source = source.split(f"func (s *Server) {handler}(", 1)[1].split("\nfunc ", 1)[0]
        schema = resolve(document, document["paths"][path][method]["requestBody"])["content"]["application/json"]["schema"]
        actual = set(resolve(document, schema)["properties"])
        require(json_fields(source, "var input struct") == actual, f"Request field drift: {handler}")
        count += 1
    for name, struct in [("CreateCA", "CreateCAInput")]:
        schema = document["components"]["requestBodies"][name]["content"]["application/json"]["schema"]
        compare("console/pki/service.go", "type " + struct + " struct", schema, name)
    # Detail/public certificate output intentionally differs from the list struct.
    source = (ROOT / "console/httpapi/handlers_pki.go").read_text()
    source = source.split("func certificateResponse(", 1)[1].split("\n}", 1)[0]
    require(set(re.findall(r'"([a-z0-9_]+)":', source)) == set(schemas["Certificate"]["properties"]),
            "Certificate detail/public response field drift")
    return count + 1


def markdown_files():
    return [ROOT / "README.md", ROOT / "target.md", ROOT / "web/README.md",
            *sorted(DOCS.glob("*.md")), DOCS / "archive/cloudflare-2026/README.md"]


def markdown_anchors(file):
    source = re.sub(r"^```[^\n]*\n.*?^```[^\n]*$", "", file.read_text(), flags=re.S | re.M)
    anchors = set(re.findall(r'<[^>]+(?:id|name)=[\"\']([^\"\']+)[\"\']', source))
    seen = set()
    for heading in re.findall(r"^ {0,3}#{1,6} +(.+?) *#* *$", source, re.M):
        heading = re.sub(r"<[^>]*>", "", heading).lower()
        slug = "".join(c for c in heading if c in " _-" or unicodedata.category(c)[0] in "LMN").replace(" ", "-")
        candidate, count = slug, 0
        while candidate in seen:
            count += 1
            candidate = f"{slug}-{count}"
        seen.add(candidate)
        anchors.add(candidate)
    return anchors


def check_links():
    count = 0
    for file in markdown_files():
        source = re.sub(r"^```[^\n]*\n.*?^```[^\n]*$", "", file.read_text(), flags=re.S | re.M)
        for target in re.findall(r"!?\[[^\]\n]*\]\(<?([^\s)>]+)>?\)", source):
            link = urlsplit(target)
            if link.scheme or link.netloc:
                continue
            resolved = (file.parent / unquote(link.path)).resolve() if link.path else file.resolve()
            require(resolved.is_relative_to(ROOT) and resolved.exists(),
                    f"Broken local link in {file.relative_to(ROOT)}: {target}")
            if link.fragment and resolved.suffix.lower() == ".md":
                require(unquote(link.fragment) in markdown_anchors(resolved),
                        f"Broken Markdown anchor in {file.relative_to(ROOT)}: {target}")
            count += 1
        for target in set(re.findall(r"\bmake (pki-console[\w-]*)", source)):
            require(re.search(r"^" + re.escape(target) + r"\s*:", (ROOT / "Makefile").read_text(), re.M),
                    f"Unknown make target in {file.relative_to(ROOT)}: {target}")
    return count


def main():
    document = yaml.load((DOCS / "openapi.yaml").read_text(), Loader=UniqueLoader)
    check_refs(document, document)
    validate(document)
    routes = check_routes(document, (ROOT / "console/httpapi/server.go").read_text())
    fields = check_fields(document)
    environment = check_environment()
    links = check_links()
    print(f"Documentation OK: OpenAPI valid; {routes} routes, {fields} JSON field mappings, "
          f"{environment} environment variables, {links} local links.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, IndexError, yaml.YAMLError, OpenAPIValidationError, ValidatorDetectError) as error:
        sys.exit(f"Documentation check failed: {error or type(error).__name__}")
