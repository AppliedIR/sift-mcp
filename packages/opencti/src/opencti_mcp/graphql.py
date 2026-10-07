"""A small OpenCTI GraphQL client for the read-only tools, without pycti.

It keeps the attribute surface the client code calls (``indicator.list``,
``stix_domain_object.read``, ``stix_core_relationship.list``, ``query``, ...),
and returns what those calls returned: a list of entity dicts, with each
connection (``{"edges": [{"node": ...}]}``) inside an entity flattened to a
list of nodes. Every selection is valid on OpenCTI 6.9 and 7.

Errors keep the classes the retry and circuit-breaker code reads:
``ConnectionError`` and ``TimeoutError`` for the transport,
``GraphQLHTTPError`` (with ``.response.status_code``) for an HTTP status,
``AuthenticationError`` for a refused token, and ``GraphQLError`` otherwise.
"""

from __future__ import annotations

from typing import Any

import httpx

COMMON = "id entity_type created modified confidence objectLabel { value }"

# The name of whatever sits at either end of a relationship or sighting.
_NAMED_SDO = (
    "... on AttackPattern { name description x_mitre_id }"
    " ... on Campaign { name description }"
    " ... on CourseOfAction { name description }"
    " ... on Grouping { name description }"
    " ... on Identity { name description }"
    " ... on Incident { name description }"
    " ... on Indicator { name description }"
    " ... on Infrastructure { name description }"
    " ... on IntrusionSet { name description }"
    " ... on Location { name description }"
    " ... on Malware { name description }"
    " ... on Report { name description }"
    " ... on ThreatActor { name description }"
    " ... on Tool { name description }"
    " ... on Vulnerability { name description }"
)
_END = (
    "{ ... on BasicObject { id entity_type } "
    + _NAMED_SDO
    + " ... on StixCyberObservable { observable_value } }"
)
_RELATIONSHIP = (
    "id relationship_type description start_time stop_time confidence created"
    f" from {_END} to {_END}"
)
_EXTERNAL_REFERENCES = "externalReferences { edges { node { source_name url } } }"

# (GraphQL root field, selection) for each list the client calls.
LISTS: dict[str, tuple[str, str]] = {
    "indicator": (
        "indicators",
        f"{COMMON} name description pattern pattern_type valid_from valid_until",
    ),
    "intrusion_set": (
        "intrusionSets",
        f"{COMMON} name description aliases first_seen last_seen goals"
        " resource_level primary_motivation",
    ),
    "threat_actor_group": (
        "threatActorsGroup",
        f"{COMMON} name description aliases sophistication resource_level"
        " primary_motivation first_seen last_seen goals",
    ),
    "malware": (
        "malwares",
        f"{COMMON} name description aliases malware_types is_family first_seen"
        " last_seen capabilities killChainPhases { phase_name }",
    ),
    "attack_pattern": (
        "attackPatterns",
        f"{COMMON} name description x_mitre_id x_mitre_platforms"
        " killChainPhases { phase_name }",
    ),
    "vulnerability": (
        "vulnerabilities",
        f"{COMMON} name description x_opencti_cvss_base_score"
        " x_opencti_cvss_base_severity",
    ),
    "report": ("reports", f"{COMMON} name description published report_types"),
    "campaign": (
        "campaigns",
        f"{COMMON} name description aliases first_seen last_seen objective",
    ),
    "tool": (
        "tools",
        f"{COMMON} name description aliases tool_types killChainPhases {{ phase_name }}",
    ),
    "infrastructure": (
        "infrastructures",
        f"{COMMON} name description aliases infrastructure_types first_seen last_seen",
    ),
    "incident": (
        "incidents",
        f"{COMMON} name description incident_type severity source objective"
        " first_seen last_seen",
    ),
    "stix_cyber_observable": (
        "stixCyberObservables",
        "id entity_type created_at observable_value objectLabel { value }"
        " ... on StixFile { hashes { algorithm hash } }",
    ),
    "stix_sighting_relationship": (
        "stixSightingRelationships",
        f"id first_seen last_seen attribute_count description confidence"
        f" from {_END} to {_END}",
    ),
    "location": (
        "locations",
        f"{COMMON} name description latitude longitude",
    ),
    "course_of_action": (
        "coursesOfAction",
        f"{COMMON} name description x_mitre_id",
    ),
    "grouping": ("groupings", f"{COMMON} name description context"),
    "note": (
        "notes",
        f"{COMMON} attribute_abstract content note_types authors likelihood",
    ),
    "stix_core_relationship": ("stixCoreRelationships", _RELATIONSHIP),
}

# identity.list(types=[...]) is answered from the root for that type.
IDENTITIES: dict[str, tuple[str, str]] = {
    "Organization": (
        "organizations",
        f"{COMMON} name description contact_information x_opencti_organization_type",
    ),
    "Sector": ("sectors", f"{COMMON} name description"),
}

READS: dict[str, tuple[str, str]] = {
    "stix_domain_object": (
        "stixDomainObject",
        f"{COMMON} {_EXTERNAL_REFERENCES} {_NAMED_SDO}"
        " ... on ThreatActorGroup { aliases sophistication resource_level"
        " primary_motivation }"
        " ... on IntrusionSet { aliases resource_level primary_motivation }"
        " ... on Malware { aliases malware_types is_family }"
        " ... on AttackPattern { killChainPhases { phase_name } }"
        " ... on Indicator { pattern pattern_type valid_from valid_until }"
        " ... on Vulnerability { x_opencti_cvss_base_score"
        " x_opencti_cvss_base_severity }"
        " ... on Campaign { aliases first_seen last_seen objective }"
        " ... on Report { published report_types }",
    ),
    "stix_cyber_observable": (
        "stixCyberObservable",
        "id entity_type created_at observable_value objectLabel { value }"
        f" {_EXTERNAL_REFERENCES}",
    ),
    "stix_core_relationship": ("stixCoreRelationship", _RELATIONSHIP),
}

# The one network call; tests replace it.
_http_post = httpx.post

_ORDER_BY = {"created", "modified", "name", "valid_from", "published", "_score"}
_ORDER_MODE = {"asc", "desc"}


class GraphQLError(Exception):
    """OpenCTI answered with GraphQL errors."""


class AuthenticationError(GraphQLError):
    """OpenCTI refused the token."""


class GraphQLHTTPError(Exception):
    """OpenCTI answered with an HTTP error status."""

    def __init__(self, response: httpx.Response) -> None:
        super().__init__(f"OpenCTI answered HTTP {response.status_code}")
        self.response = response


def _flatten(value: Any) -> Any:
    """Connections inside an entity become lists of their nodes."""
    if isinstance(value, dict):
        if set(value) == {"edges"} and isinstance(value["edges"], list):
            return [
                _flatten(edge.get("node"))
                for edge in value["edges"]
                if isinstance(edge, dict)
            ]
        return {key: _flatten(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_flatten(item) for item in value]
    return value


class _Entity:
    def __init__(self, client: GraphQLClient, name: str) -> None:
        self._client = client
        self._name = name

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        if self._name == "identity":
            types = kwargs.pop("types", None) or []
            if len(types) != 1 or types[0] not in IDENTITIES:
                raise ValueError(
                    f"identity.list supports one type of {sorted(IDENTITIES)}"
                )
            root, selection = IDENTITIES[types[0]]
        else:
            root, selection = LISTS[self._name]
        return self._client._list(root, selection, **kwargs)

    def read(self, id: str) -> dict[str, Any] | None:  # noqa: A002 (pycti's name)
        root, selection = READS[self._name]
        data = self._client.query(
            f"query Read($id: String!) {{ {root}(id: $id) {{ {selection} }} }}",
            {"id": id},
        )["data"]
        node = data.get(root)
        return _flatten(node) if isinstance(node, dict) else None


class GraphQLClient:
    """The read calls the OpenCTI tools make, over OpenCTI's GraphQL API."""

    def __init__(
        self, url: str, token: str, *, requests_timeout: float, ssl_verify: bool = True
    ) -> None:
        self._url = f"{url.rstrip('/')}/graphql"
        self._token = token
        self.requests_timeout = requests_timeout  # the adaptive timeout sets it
        self._ssl_verify = ssl_verify
        for name in (*LISTS, *READS, "identity"):
            setattr(self, name, _Entity(self, name))

    def query(self, query: str, variables: dict | None = None) -> dict[str, Any]:
        """Run a GraphQL request; returns the whole reply (``{"data": ...}``)."""
        try:
            response = _http_post(
                self._url,
                json={"query": query, "variables": variables or {}},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self.requests_timeout,
                verify=self._ssl_verify,
            )
        except httpx.TimeoutException as e:
            raise TimeoutError(f"OpenCTI did not answer in time: {e}") from e
        except httpx.TransportError as e:
            raise ConnectionError(f"Can't reach OpenCTI: {type(e).__name__}") from e
        if response.status_code != 200:
            raise GraphQLHTTPError(response)
        try:
            body = response.json()
        except ValueError as e:
            raise GraphQLError("OpenCTI's reply is not JSON") from e
        if not isinstance(body, dict):
            raise GraphQLError("OpenCTI's reply has an unexpected shape")
        errors = body.get("errors")
        if errors:
            first = errors[0] if isinstance(errors, list) and errors else {}
            first = first if isinstance(first, dict) else {}
            code = (first.get("extensions") or {}).get("code") or first.get("name")
            message = f"{code}: {first.get('message', '')}"[:300]
            if code in ("AUTH_REQUIRED", "FORBIDDEN_ACCESS"):
                raise AuthenticationError(message)
            raise GraphQLError(message)
        if not isinstance(body.get("data"), dict):
            raise GraphQLError("OpenCTI's reply has no data")
        return body

    def _list(
        self,
        root: str,
        selection: str,
        *,
        search: str | None = None,
        first: int = 100,
        filters: dict | None = None,
        orderBy: str | None = None,  # noqa: N803 (pycti's names)
        orderMode: str | None = None,  # noqa: N803
        types: list[str] | None = None,
        fromId: str | list[str] | None = None,  # noqa: N803
        toId: str | list[str] | None = None,  # noqa: N803
        relationship_type: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        params = ["$first: Int"]
        args = ["first: $first"]
        variables: dict[str, Any] = {"first": int(first)}
        for name, kind, value in (
            ("search", "String", search),
            ("filters", "FilterGroup", filters),
            ("types", "[String]", types),
            ("fromId", "[String]", [fromId] if isinstance(fromId, str) else fromId),
            ("toId", "[String]", [toId] if isinstance(toId, str) else toId),
            ("relationship_type", "[String]", relationship_type),
        ):
            if value is not None:
                params.append(f"${name}: {kind}")
                args.append(f"{name}: ${name}")
                variables[name] = value
        # Ordering is an enum literal of the root's own type; only known
        # values are written into the query.
        if orderBy is not None:
            if orderBy not in _ORDER_BY:
                raise ValueError(f"unsupported orderBy: {orderBy}")
            args.append(f"orderBy: {orderBy}")
        if orderMode is not None:
            if orderMode not in _ORDER_MODE:
                raise ValueError(f"unsupported orderMode: {orderMode}")
            args.append(f"orderMode: {orderMode}")
        query = (
            f"query List({', '.join(params)}) {{ {root}({', '.join(args)}) "
            f"{{ edges {{ node {{ {selection} }} }} }} }}"
        )
        connection = self.query(query, variables)["data"].get(root)
        if connection is None:
            return []
        if not isinstance(connection, dict) or not isinstance(
            connection.get("edges"), list
        ):
            raise GraphQLError(f"OpenCTI's {root} reply has an unexpected shape")
        return [
            _flatten(edge["node"])
            for edge in connection["edges"]
            if isinstance(edge, dict) and isinstance(edge.get("node"), dict)
        ]
