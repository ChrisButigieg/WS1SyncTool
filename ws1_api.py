"""
WS1 UEM API Client
Supports Basic Auth (username:password + API key) and P12 certificate authentication.
"""

import base64
import logging
import os
import tempfile
from typing import Dict, List, Optional, Tuple, Union

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

log = logging.getLogger(__name__)

_ZERO_UUID = "00000000-0000-0000-0000-000000000000"

# ------------------------------------------------------------------ auth helpers

def _build_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _extract_p12_to_pem(p12_path: str, p12_password: str) -> Tuple[str, str]:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, pkcs12,
    )
    with open(p12_path, "rb") as f:
        p12_data = f.read()
    pw_bytes = p12_password.encode() if p12_password else None
    private_key, certificate, _ = pkcs12.load_key_and_certificates(
        p12_data, pw_bytes, default_backend()
    )
    cert_tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    key_tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    cert_tmp.write(certificate.public_bytes(Encoding.PEM))
    cert_tmp.close()
    key_tmp.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    key_tmp.close()
    return cert_tmp.name, key_tmp.name


# ------------------------------------------------------------------ response helpers

_KNOWN_LIST_KEYS = [
    "SearchResults", "Results", "Result", "Value", "values",
    "Items", "items", "List", "list", "Data", "data",
    "OrganizationGroups", "organizationGroups", "LocationGroups", "locationGroups",
    "SmartGroups", "smartGroups",
    "CompliancePolicies", "compliancePolicies", "Policies", "policies",
    "Policy", "policy", "CompliancePolicy", "compliancePolicy",
    "Application", "Applications", "applications",
    "Scripts", "scripts", "Script",
    "Sensors", "sensors", "DeviceSensors", "deviceSensors",
    "result_set", "ResultSet",
    "CustomAttributes", "customAttributes", "CustomAttribute",
    "Tags", "tags",
    "Products", "products",
    "Profiles", "profiles",
    "Devices", "devices",
]


def _extract_items(data: Union[dict, list, None]) -> List[dict]:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in _KNOWN_LIST_KEYS:
            if key in data and isinstance(data[key], list):
                return data[key]
        for key, val in data.items():
            if isinstance(val, list) and val:
                return val
    return []


def _is_valid_uuid(val) -> bool:
    return bool(val and isinstance(val, str) and len(val) > 8 and val != _ZERO_UUID)


def _extract_og_id(og: dict) -> Optional[int]:
    """Extract integer OG id from V1 nested or V2 flat format."""
    val = og.get("Id")
    if isinstance(val, int):
        return val
    if isinstance(val, dict):
        inner = val.get("Value")
        if isinstance(inner, int):
            return inner
    return None


def _extract_og_uuid(og: dict) -> Optional[str]:
    for field in ("Uuid", "OrganizationGroupUuid", "GroupUuid", "UUID"):
        val = og.get(field)
        if _is_valid_uuid(val):
            return val
    return None


# ------------------------------------------------------------------ client

class WS1Client:
    """Workspace ONE UEM REST API client."""

    PAGE_SIZE = 500

    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
        api_key: str,
        p12_path: Optional[str] = None,
        p12_password: Optional[str] = None,
        verify_ssl: bool = True,
        on_request=None,    # callable(method, path, status, count) — live log hook
        is_cancelled=None,  # callable() → bool — cancel poll hook
    ):
        self.base_url = server_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self._cert_files: Optional[Tuple[str, str]] = None

        # Cached lookups — populated on first use, reused per client instance
        self._cached_og_id: Optional[int] = None
        self._cached_og_uuid: Optional[str] = None
        self._cached_og_tree: Optional[List[dict]] = None             # full flat OG list
        self._cached_og_name_map: Optional[Dict[str, dict]] = None   # name → {id, uuid}
        self._cached_tag_name_map: Optional[Dict[str, int]] = None   # name → id

        # Cross-environment OG ID remap: prod_og_id → this_env_og_id
        # Built from matching PROD OG list against this env's OG tree by GroupId then Name.
        # Injected by the sync route before creating items that reference OG IDs.
        self._og_prod_to_uat: Dict[int, int] = {}
        self._og_prod_to_uat_uuid: Dict[int, Optional[str]] = {}

        # Cross-environment Smart Group ID remap: prod_sg_id → this_env_sg_id
        # Built by matching PROD SG names against UAT SG names.
        # Used by create_profile to remap assignment SmartGroupIds.
        self._sg_prod_to_uat: Dict[int, int] = {}

        # Live-log / cancellation hooks — set by the caller (e.g. the Flask route)
        # on_request(method, path, status_code, item_count) — called after each HTTP round-trip
        # is_cancelled() → bool — polled before each HTTP call; raise to abort cleanly
        self._on_request = on_request
        self._is_cancelled = is_cancelled

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Authorization": _build_basic_auth_header(username, password),
            "aw-tenant-code": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

        if p12_path and os.path.isfile(p12_path):
            cert_pem, key_pem = _extract_p12_to_pem(p12_path, p12_password or "")
            self._cert_files = (cert_pem, key_pem)
            self.session.cert = self._cert_files
            log.info("P12 certificate loaded from %s", p12_path)

    # ------------------------------------------------------------------ HTTP

    def _check_cancel(self):
        if self._is_cancelled and self._is_cancelled():
            raise InterruptedError("Operation cancelled by user")

    def _get_raw(self, path: str, params: dict = None, extra_headers: dict = None,
                 silent: bool = False) -> Tuple[Union[dict, list], int]:
        self._check_cancel()
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, params=params, headers=extra_headers or {}, timeout=30)
            status = resp.status_code
            try:
                body = resp.json()
            except Exception:
                body = {"_raw_text": resp.text[:2000]}
            if status >= 400:
                log.warning("GET %s → %d", url, status)
            if not silent and self._on_request:
                self._on_request("GET", path, status, len(_extract_items(body)))
            return body, status
        except InterruptedError:
            raise
        except Exception as exc:
            log.error("GET %s failed: %s", url, exc)
            if not silent and self._on_request:
                self._on_request("GET", path, 0, 0)
            return {"_error": str(exc)}, 0

    def _get(self, path: str, params: dict = None) -> Union[dict, list]:
        self._check_cancel()
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return {}

    def _post(self, path: str, payload: dict) -> dict:
        self._check_cancel()
        url = f"{self.base_url}{path}"
        resp = self.session.post(url, json=payload, timeout=60)
        if self._on_request:
            self._on_request("POST", path, resp.status_code, 0)
        if resp.status_code >= 400:
            try:
                err_body = resp.json()
                detail = (err_body.get("message") or err_body.get("Message")
                          or err_body.get("errorCode") or err_body.get("ErrorCode")
                          or str(err_body)[:400])
            except Exception:
                detail = resp.text[:400]
            raise requests.HTTPError(
                f"HTTP {resp.status_code} — {detail}", response=resp
            )
        try:
            return resp.json()
        except Exception:
            return {}

    # ------------------------------------------------------------------ multi-path fetch

    def _fetch_from_paths(
        self,
        paths: List[str],
        base_params: Optional[dict] = None,
        paged: bool = True,
        try_no_params: bool = False,
        try_v2_header: bool = False,
        page_size_key: str = "pagesize",
    ) -> Tuple[List[dict], dict]:
        with_params = {page_size_key: self.PAGE_SIZE, **(base_params or {})}
        param_sets = [with_params]
        if try_no_params:
            param_sets.append({})

        header_sets: List[Tuple[str, dict]] = [("v1", {})]
        if try_v2_header:
            header_sets.append(("v2", {"Accept": "application/json;version=2"}))

        debug: Dict[str, dict] = {}

        for path in paths:
            for params in param_sets:
                for hdr_label, extra_headers in header_sets:
                    suffix = []
                    if try_no_params and not params:
                        suffix.append("no-pagination")
                    if try_v2_header and hdr_label == "v2":
                        suffix.append("v2")
                    label = path + (f" [{','.join(suffix)}]" if suffix else "")

                    body, status = self._get_raw(path, params=params or None, extra_headers=extra_headers or None)
                    items = _extract_items(body)

                    debug[label] = {
                        "status": status,
                        "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                        "count": len(items),
                    }

                    if status == 404:
                        break
                    if status >= 400:
                        continue

                    if items:
                        if paged:
                            items = self._paginate(path, items, with_params, page_size_key=page_size_key)
                        return items, debug

                    log.debug("Path %s (%s, params=%s) → 200 but 0 items; continuing", path, hdr_label, params)
                else:
                    continue
                break

        return [], debug

    def _paginate(self, path: str, first_page: List[dict], params: dict, page_size_key: str = "pagesize") -> List[dict]:
        page_size = params.get(page_size_key, self.PAGE_SIZE)
        if len(first_page) < page_size:
            return first_page
        all_items = list(first_page)
        page = 1
        while True:
            body, status = self._get_raw(path, params={**params, "page": page})
            if status >= 400:
                break
            batch = _extract_items(body)
            if not batch:
                break
            all_items.extend(batch)
            if len(batch) < page_size:
                break
            page += 1
        return all_items

    # ------------------------------------------------------------------ test / probe

    def test_connection(self) -> dict:
        return self._get("/api/system/info")

    def probe_endpoint(self, path: str, params: dict = None) -> dict:
        body, status = self._get_raw(path, params=params)
        items = _extract_items(body)
        return {
            "path": path, "status": status, "raw": body,
            "extracted_count": len(items), "extracted_sample": items[:3],
        }

    # ------------------------------------------------------------------ root OG helpers

    def _get_root_og(self) -> dict:
        """Return the root OG object, preferring V2 API for real UUIDs."""
        body, status = self._get_raw(
            "/api/system/groups/search", params={"pagesize": 1},
            extra_headers={"Accept": "application/json;version=2"},
        )
        if status < 400:
            items = _extract_items(body)
            if items:
                return items[0]
        body, status = self._get_raw("/api/system/groups/search", params={"pagesize": 1})
        items = _extract_items(body)
        return items[0] if items else {}

    def _get_root_og_id(self) -> Optional[int]:
        if self._cached_og_id is not None:
            return self._cached_og_id
        og = self._get_root_og()
        for field in ("Id", "OrganizationGroupId", "LocationGroupId"):
            val = og.get(field)
            if isinstance(val, int):
                self._cached_og_id = val
                return val
            if isinstance(val, dict):
                inner = val.get("Value")
                if isinstance(inner, int):
                    self._cached_og_id = inner
                    return inner
        log.warning("Could not determine root OG id; fields: %s", list(og.keys()))
        return None

    def _get_root_og_uuid(self) -> Optional[str]:
        if self._cached_og_uuid is not None:
            return self._cached_og_uuid
        og = self._get_root_og()
        for field in ("Uuid", "OrganizationGroupUuid", "GroupUuid", "UUID"):
            val = og.get(field)
            if _is_valid_uuid(val):
                self._cached_og_uuid = val
                return val
        log.warning("Could not determine root OG UUID; fields: %s", list(og.keys()))
        return None

    # ------------------------------------------------------------------ OG full-tree helpers

    def _fetch_og_tree(self) -> List[dict]:
        """
        Return all OGs in the hierarchy as a flat list using the children endpoint.
        This endpoint returns the complete subtree in a single response (no pagination).
        Result is cached on the client instance — subsequent calls are free.
        """
        if self._cached_og_tree is not None:
            return self._cached_og_tree

        root_id = self._get_root_og_id()
        if not root_id:
            body, _ = self._get_raw("/api/system/groups/search",
                                    params={"pagesize": self.PAGE_SIZE})
            self._cached_og_tree = _extract_items(body)
            return self._cached_og_tree

        # Single call — the children endpoint returns the full subtree at once.
        body, status = self._get_raw(
            f"/api/system/groups/{root_id}/children",
            params={"pagesize": self.PAGE_SIZE},
        )
        if status < 400:
            self._cached_og_tree = body if isinstance(body, list) else _extract_items(body)
        else:
            self._cached_og_tree = []

        return self._cached_og_tree

    def _build_og_id_info_map(self) -> Dict[int, dict]:
        """Build {og_id: {uuid, parent_id}} from the cached OG tree. Used for LCA lookups."""
        ogs = self._fetch_og_tree()
        result: Dict[int, dict] = {}
        for og in ogs:
            og_id = _extract_og_id(og)
            if og_id is None:
                continue
            parent_block = og.get("ParentLocationGroup", {})
            parent_id = _extract_og_id(parent_block) if parent_block else None
            result[og_id] = {"uuid": _extract_og_uuid(og), "parent_id": parent_id}
        return result

    def _find_lca_id(self, og_ids: List[int], id_info: Dict[int, dict]) -> Optional[int]:
        """
        Return the lowest common ancestor OG ID for a set of OG IDs.
        Traverses parent chains and returns the deepest node common to all chains.
        """
        if not og_ids:
            return None

        def ancestor_chain(og_id: int) -> List[int]:
            chain: List[int] = []
            current: Optional[int] = og_id
            seen: set = set()
            while current is not None and current not in seen:
                chain.append(current)
                seen.add(current)
                current = id_info.get(current, {}).get("parent_id")
            return chain

        chains = [ancestor_chain(oid) for oid in og_ids]
        common = set(chains[0])
        for chain in chains[1:]:
            common &= set(chain)
        if not common:
            return None
        for node in chains[0]:
            if node in common:
                return node
        return None

    def _build_og_name_map(self) -> Dict[str, dict]:
        """
        Build and cache a name → {id, uuid} map for all OGs in THIS environment.
        Used during sync to remap prod OG ID references to UAT OG IDs by name.
        """
        if self._cached_og_name_map is not None:
            return self._cached_og_name_map

        ogs = self._fetch_og_tree()
        name_map: Dict[str, dict] = {}
        for og in ogs:
            name = og.get("Name")
            if not name:
                continue
            og_id = _extract_og_id(og)
            og_uuid = _extract_og_uuid(og)
            if og_id:
                name_map[name] = {"id": og_id, "uuid": og_uuid}

        self._cached_og_name_map = name_map
        log.info("Built OG name map with %d entries", len(name_map))
        return name_map

    def _build_tag_name_map(self) -> Dict[str, int]:
        """
        Build and cache a name → id map for all tags in THIS environment.
        Used during sync to remap prod tag IDs to UAT tag IDs by name.
        """
        if self._cached_tag_name_map is not None:
            return self._cached_tag_name_map

        og_id = self._get_root_og_id()
        body, _ = self._get_raw(
            f"/api/system/groups/{og_id}/tags" if og_id else "/api/mdm/tags/search"
        )
        tags = _extract_items(body)

        name_map: Dict[str, int] = {}
        for tag in tags:
            name = tag.get("TagName") or tag.get("Name") or tag.get("name")
            tag_id = tag.get("Id") or tag.get("TagId")
            if name and tag_id is not None:
                name_map[name] = int(tag_id)

        self._cached_tag_name_map = name_map
        log.info("Built tag name map with %d entries", len(name_map))
        return name_map

    def build_og_remap(self, prod_ogs: List[dict]) -> None:
        """
        Build a PROD→this-env OG ID remap table from a list of PROD OG items.

        Matching priority:
          1. GroupId short code (e.g. "DAF", "446AW") — most stable across envs
          2. Name — fallback when GroupId differs

        The root OG is included in the lookup even though it does not appear in
        the /children response, so SGs managed by root are translated correctly.
        """
        this_env_ogs = self._fetch_og_tree()

        # Build lookup indexes for this environment's OGs
        this_by_group_id: Dict[str, dict] = {}
        this_by_name: Dict[str, dict] = {}

        def _index(og: dict) -> None:
            og_id = _extract_og_id(og)
            if not og_id:
                return
            entry = {"id": og_id, "uuid": _extract_og_uuid(og)}
            gid = og.get("GroupId")
            if gid:
                this_by_group_id[gid] = entry
            name = og.get("Name")
            if name:
                this_by_name[name] = entry

        for og in this_env_ogs:
            _index(og)

        # Also index the root OG — it is not returned by /children
        root_og = self._get_root_og()
        if root_og:
            _index(root_og)

        matched = 0
        for prod_og in prod_ogs:
            prod_id = prod_og.get("_Id") or _extract_og_id(prod_og)
            if not prod_id:
                continue
            gid = prod_og.get("GroupId")
            match = (this_by_group_id.get(gid) if gid else None) or \
                    this_by_name.get(prod_og.get("Name") or "")
            if match:
                self._og_prod_to_uat[prod_id] = match["id"]
                self._og_prod_to_uat_uuid[prod_id] = match["uuid"]
                matched += 1

        log.info("OG remap: matched %d of %d PROD OGs to this env", matched, len(prod_ogs))

    def _resolve_og_id(self, prod_id, name: Optional[str],
                       og_map: Dict[str, dict]) -> Tuple[Optional[int], Optional[str]]:
        """
        Translate a PROD OG ID to this env's OG ID.
        Tries the remap table first (GroupId/Name matched), then og_map by name.
        Returns (id, uuid) or (None, None) if not found.
        """
        if prod_id:
            try:
                prod_id_int = int(prod_id)
            except (TypeError, ValueError):
                prod_id_int = None
            if prod_id_int and prod_id_int in self._og_prod_to_uat:
                uat_id = self._og_prod_to_uat[prod_id_int]
                return uat_id, self._og_prod_to_uat_uuid.get(prod_id_int)
        if name and name in og_map:
            entry = og_map[name]
            return entry["id"], entry.get("uuid")
        return None, None

    def build_sg_remap(self, prod_sgs: List[dict]) -> None:
        """
        Build a PROD→this-env Smart Group ID remap table.
        Matches by Name. Used by create_profile to translate SG assignment IDs.
        Fetches this env's current SG list internally.
        """
        uat_sgs, _ = self._fetch_from_paths(
            ["/api/mdm/smartgroups/search", "/api/mdm/smartgroups"], paged=False
        )
        uat_by_name: Dict[str, int] = {}
        for sg in uat_sgs:
            name = sg.get("Name") or sg.get("SmartGroupName")
            sg_id = sg.get("SmartGroupID") or sg.get("Id")
            if name and sg_id:
                uat_by_name[name] = int(sg_id)

        matched = 0
        for prod_sg in prod_sgs:
            prod_id = prod_sg.get("SmartGroupID") or prod_sg.get("Id")
            name = prod_sg.get("Name") or prod_sg.get("SmartGroupName")
            if not prod_id or not name:
                continue
            uat_id = uat_by_name.get(name)
            if uat_id:
                self._sg_prod_to_uat[int(prod_id)] = uat_id
                matched += 1

        log.info("SG remap: matched %d of %d PROD SGs to this env", matched, len(prod_sgs))

    def _resolve_sg_id(self, prod_id) -> Optional[int]:
        """Translate a PROD Smart Group ID to this env's SG ID via the remap table."""
        if prod_id is None:
            return None
        try:
            return self._sg_prod_to_uat.get(int(prod_id))
        except (TypeError, ValueError):
            return None

    def _get_all_og_uuids(self) -> List[str]:
        """Return UUIDs for all OGs — used for sensors/scripts sweep."""
        ogs = self._fetch_og_tree()
        uuids: List[str] = []
        for og in ogs:
            uuid = _extract_og_uuid(og)
            if uuid:
                uuids.append(uuid)
        log.info("Collected %d OG UUIDs", len(uuids))
        return uuids

    # ------------------------------------------------------------------ fetch methods

    def get_org_types(self) -> Tuple[List[dict], dict]:
        """
        Derive the unique LocationGroupType values from the OG hierarchy.
        Marks each type as Standard (built-in) or Custom (must be manually
        created in the target environment before OGs of that type can be synced).
        """
        ogs = self._fetch_og_tree()
        debug = {
            "/api/system/groups/{root}/children [org-types]": {
                "status": 200, "keys": ["derived"], "count": len(ogs),
            }
        }

        from collections import Counter
        type_counts = Counter(og.get("LocationGroupType", "Unknown") for og in ogs)

        items = []
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            is_standard = t in STANDARD_OG_TYPES
            items.append({
                "Type": t,
                "Count": c,
                "IsStandard": is_standard,
                "Status": "Standard" if is_standard else "⚠️ Custom — add manually in UAT",
                "Description": _OG_TYPE_DESC.get(t, "Non-standard type — must be added manually in UAT before syncing OGs"),
            })

        return items, debug

    def get_organizational_groups(self) -> Tuple[List[dict], dict]:
        """
        Fetch all OGs with parent-child hierarchy info via the children endpoint.
        Each OG is enriched with _ParentId (int) and _ParentName (str) for
        use when creating OGs in a target environment.
        """
        all_ogs = self._fetch_og_tree()
        debug = {
            "/api/system/groups/{root}/children": {
                "status": 200,
                "keys": ["children-traversal"],
                "count": len(all_ogs),
            }
        }

        if not all_ogs:
            items2, debug2 = self._fetch_from_paths(["/api/system/groups/search"], paged=True)
            return items2, {**debug, **debug2}

        # Build id → name lookup to populate _ParentName on each OG
        id_to_name: Dict[int, str] = {}
        for og in all_ogs:
            og_id = _extract_og_id(og)
            if og_id and og.get("Name"):
                id_to_name[og_id] = og["Name"]

        enriched: List[dict] = []
        for og in all_ogs:
            og = dict(og)
            # Normalize Id to a plain integer in a consistent field
            og["_Id"] = _extract_og_id(og)
            og["_Uuid"] = _extract_og_uuid(og)
            # Extract parent info from ParentLocationGroup block
            parent_block = og.get("ParentLocationGroup", {})
            parent_id = _extract_og_id(parent_block) if parent_block else None
            og["_ParentId"] = parent_id
            og["_ParentName"] = id_to_name.get(parent_id) if parent_id else None
            enriched.append(og)

        return enriched, debug

    def get_profiles(self) -> Tuple[List[dict], dict]:
        """
        Fetch profile list then enrich each with full detail.
        Tries multiple detail-endpoint variants before falling back to the search summary.
        """
        items, debug = self._fetch_from_paths([
            "/api/mdm/profiles/search",
            "/api/mdm/profiles",
        ])
        enriched: List[dict] = []
        for profile in items:
            profile_id = (profile.get("ProfileId")
                          or _extract_og_id(profile)
                          or profile.get("Id"))
            profile_uuid = _extract_og_uuid(profile)
            profile_name = profile.get("ProfileName") or profile.get("Name") or ""

            detail_paths: List[str] = []
            if profile_id:
                detail_paths += [
                    f"/api/mdm/profiles/{profile_id}",
                    f"/api/mdm/profiles/detail/{profile_id}",
                ]
            if profile_uuid:
                detail_paths += [
                    f"/api/mdm/profiles/{profile_uuid}",
                ]

            got_detail = False
            for dpath in detail_paths:
                body, status = self._get_raw(dpath, silent=True)
                if status < 400 and isinstance(body, dict) and body and "_raw_text" not in body:
                    enriched.append(body)
                    got_detail = True
                    break

            if not got_detail:
                # Fall back to name-based search to get a richer record
                if profile_name:
                    body, status = self._get_raw(
                        "/api/mdm/profiles/search",
                        params={"profilename": profile_name, "pagesize": 1},
                        silent=True,
                    )
                    if status < 400:
                        results = _extract_items(body)
                        if results:
                            enriched.append(results[0])
                            continue
                enriched.append(profile)

        if enriched:
            debug["_enriched"] = {"status": 200, "keys": ["detail-per-item"],
                                  "count": len(enriched)}
        return enriched, debug

    def get_smart_groups(self) -> Tuple[List[dict], dict]:
        """
        Fetch smart group list then enrich each with full detail (CriteriaType,
        DeviceAdditions, UserGroups, Tags, OrganizationGroups, etc.).
        The search endpoint only returns summary fields.
        """
        items, debug = self._fetch_from_paths([
            "/api/mdm/smartgroups/search",
            "/api/mdm/smartgroups",
        ], paged=False)

        enriched: List[dict] = []
        for sg in items:
            sg_id = sg.get("SmartGroupID")
            if not sg_id:
                enriched.append(sg)
                continue
            body, status = self._get_raw(f"/api/mdm/smartgroups/{sg_id}")
            if status < 400 and isinstance(body, dict) and body:
                enriched.append(body)
            else:
                enriched.append(sg)

        if enriched:
            debug["_enriched"] = {"status": 200, "keys": ["detail-per-item"], "count": len(enriched)}
        return enriched, debug

    def get_compliance_policies(self) -> Tuple[List[dict], dict]:
        return self._fetch_from_paths([
            "/api/mdm/compliancepolicies",
            "/api/mdm/compliancepolicies/search",
        ], try_no_params=True, try_v2_header=True)

    def get_apps_internal(self) -> Tuple[List[dict], dict]:
        return self._fetch_from_paths([
            "/api/mam/apps/search",
            "/api/mam/apps/internal/search",
            "/api/mam/apps/internal",
        ])

    def get_apps_public(self) -> Tuple[List[dict], dict]:
        items, debug = self._fetch_from_paths([
            "/api/mam/apps/public/search",
            "/api/mam/apps/public",
        ])
        if not items:
            for type_val in ("public", "2", "AppStore"):
                for param_key in ("applicationType", "type", "AppType"):
                    body, status = self._get_raw(
                        "/api/mam/apps/search",
                        params={"pagesize": self.PAGE_SIZE, param_key: type_val},
                    )
                    candidates = _extract_items(body)
                    label = f"/api/mam/apps/search [{param_key}={type_val}]"
                    debug[label] = {
                        "status": status,
                        "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                        "count": len(candidates),
                    }
                    if candidates:
                        return candidates, debug
        return items, debug

    def get_apps_purchased(self) -> Tuple[List[dict], dict]:
        items, debug = self._fetch_from_paths([
            "/api/mam/apps/purchased/search",
            "/api/mam/apps/purchased",
            "/api/mam/apps/vpp/search",
            "/api/mam/apps/vpp",
        ])
        if not items:
            for type_val in ("Purchased", "purchased", "3", "VPP", "vpp"):
                for param_key in ("applicationType", "type", "AppType"):
                    body, status = self._get_raw(
                        "/api/mam/apps/search",
                        params={"pagesize": self.PAGE_SIZE, param_key: type_val},
                    )
                    candidates = _extract_items(body)
                    label = f"/api/mam/apps/search [{param_key}={type_val}]"
                    debug[label] = {
                        "status": status,
                        "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                        "count": len(candidates),
                    }
                    if candidates:
                        return candidates, debug
        return items, debug

    def get_scripts(self) -> Tuple[List[dict], dict]:
        debug: Dict[str, dict] = {}

        # Try standard search/list endpoints first
        for path in ("/api/mdm/scripts/search", "/api/mdm/scripts"):
            body, status = self._get_raw(path, params={"pagesize": self.PAGE_SIZE})
            items = _extract_items(body)
            debug[path] = {
                "status": status,
                "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                "count": len(items),
            }
            if items:
                return self._paginate(path, items, {"pagesize": self.PAGE_SIZE}), debug

        # Fall back to per-OG UUID sweep only if standard endpoints returned nothing
        root_uuid = self._get_root_og_uuid()
        if not root_uuid:
            return [], debug

        log.info("Sweeping all OGs for scripts…")
        seen: set = set()
        all_items: List[dict] = []
        script_params = {"page_size": self.PAGE_SIZE}
        og_uuids = self._get_all_og_uuids()
        for uuid in og_uuids:
            path = f"/api/mdm/groups/{uuid}/scripts"
            body, status = self._get_raw(path, params=script_params, silent=True)
            if status >= 400:
                continue
            batch = _extract_items(body)
            for s in batch:
                uid = s.get("script_uuid") or s.get("Uuid") or s.get("ScriptId") or str(s)
                if uid not in seen:
                    seen.add(uid)
                    all_items.append(s)

        # Emit one summary log entry for the entire sweep
        if self._on_request:
            self._on_request("GET", f"/api/mdm/groups/{{uuid}}/scripts [swept {len(og_uuids)} OGs]",
                             200, len(all_items))
        debug["/api/mdm/groups/{uuid}/scripts [sweep]"] = {
            "status": 200, "keys": ["sweep"], "count": len(all_items),
        }
        return all_items, debug

    def get_sensors(self) -> Tuple[List[dict], dict]:
        debug: Dict[str, dict] = {}
        sensor_params = {"pageSize": self.PAGE_SIZE}

        # Try standard list endpoints first
        for path in ("/api/mdm/devicesensors/list", "/api/mdm/devicesensors"):
            body, status = self._get_raw(path, params=sensor_params)
            items = _extract_items(body)
            debug[path] = {
                "status": status,
                "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                "count": len(items),
            }
            if items:
                return self._paginate(path, items, sensor_params, page_size_key="pageSize"), debug

        # Fall back to root-UUID path, then per-OG sweep
        root_uuid = self._get_root_og_uuid()
        if root_uuid:
            path = f"/api/mdm/devicesensors/list/{root_uuid}"
            body, status = self._get_raw(path, params=sensor_params)
            items = _extract_items(body)
            debug[path] = {
                "status": status,
                "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                "count": len(items),
            }
            if items:
                return self._paginate(path, items, sensor_params, page_size_key="pageSize"), debug

        if not root_uuid:
            return [], debug

        log.info("Sweeping all OGs for sensors…")
        seen: set = set()
        all_items: List[dict] = []
        og_uuids = self._get_all_og_uuids()
        for uuid in og_uuids:
            path = f"/api/mdm/devicesensors/list/{uuid}"
            body, status = self._get_raw(path, params=sensor_params, silent=True)
            if status >= 400:
                continue
            batch = _extract_items(body)
            for s in batch:
                uid = s.get("uuid") or s.get("Uuid") or s.get("name") or str(s)
                if uid not in seen:
                    seen.add(uid)
                    all_items.append(s)

        if self._on_request:
            self._on_request("GET", f"/api/mdm/devicesensors/list/{{uuid}} [swept {len(og_uuids)} OGs]",
                             200, len(all_items))
        debug["/api/mdm/devicesensors/list/{uuid} [sweep]"] = {
            "status": 200, "keys": ["sweep"], "count": len(all_items),
        }
        return all_items, debug

    def get_tags(self) -> Tuple[List[dict], dict]:
        debug: Dict[str, dict] = {}
        og_id = self._get_root_og_id()

        if og_id:
            path = f"/api/system/groups/{og_id}/tags"
            body, status = self._get_raw(path)
            items = _extract_items(body)
            debug[path] = {
                "status": status,
                "keys": list(body.keys()) if isinstance(body, dict) else f"array[{len(body)}]",
                "count": len(items),
            }
            if items:
                return items, debug

        base_params = {"organizationgroupid": og_id} if og_id else {}
        items2, debug2 = self._fetch_from_paths(
            ["/api/mdm/tags/search", "/api/mdm/tags"],
            base_params=base_params, paged=False, try_no_params=(not og_id),
        )
        debug.update(debug2)
        return items2, debug

    def get_product_provisioning(self) -> Tuple[List[dict], dict]:
        return self._fetch_from_paths([
            "/api/mdm/products/search",
            "/api/mdm/products",
        ])

    # ------------------------------------------------------------------ sync / create

    def create_organizational_group(self, payload: dict) -> dict:
        """
        Create an OG in this environment under the correct parent.
        Parent is resolved by matching _ParentName against this env's OG name map.
        Falls back to root OG if parent not found.
        After creation, adds the new OG to the name map so subsequent children
        can find it without a cache miss.
        """
        og_map = self._build_og_name_map()
        root_id = self._get_root_og_id()

        # Determine parent OG ID in this environment
        parent_name = payload.get("_ParentName")
        if parent_name and parent_name in og_map:
            parent_id = og_map[parent_name]["id"]
        else:
            parent_id = root_id
            if parent_name:
                log.warning("OG parent '%s' not found in target env, using root OG", parent_name)

        if not parent_id:
            raise ValueError("Cannot determine parent OG for creation")

        body = {
            "Name": payload.get("Name", ""),
            "GroupId": payload.get("GroupId", ""),
            "LocationGroupType": payload.get("LocationGroupType", "Container"),
            "Country": payload.get("Country", "United States"),
            "Locale": payload.get("Locale", "English (United States)"),
        }

        try:
            result = self._post(f"/api/system/groups/{parent_id}", body)
        except requests.HTTPError as exc:
            err = str(exc)
            if "Invalid Organization Group type" in err:
                # Custom type not registered in target env — fall back to Container so the
                # OG is still created in the right place; admin can fix the type later.
                log.warning("OG '%s' type '%s' not found in UAT; retrying as Container",
                            body["Name"], body["LocationGroupType"])
                body["LocationGroupType"] = "Container"
                result = self._post(f"/api/system/groups/{parent_id}", body)
            elif "already in use" in err.lower():
                # GroupId collision — generate a unique fallback code from the OG name
                import re as _re
                safe_id = _re.sub(r"[^A-Za-z0-9]", "", body["Name"])[:20] + "_S"
                log.warning("OG '%s' GroupId '%s' already in use; retrying with '%s'",
                            body["Name"], body["GroupId"], safe_id)
                body["GroupId"] = safe_id
                result = self._post(f"/api/system/groups/{parent_id}", body)
            else:
                raise

        # Extract the new OG's ID from the response and update the name map
        # so children processed later in the same sync can find this parent.
        new_id: Optional[int] = None
        new_uuid: Optional[str] = None
        if isinstance(result, int):
            new_id = result
        elif isinstance(result, dict):
            new_id = _extract_og_id(result)
            if new_id is None:
                for field in ("Value", "LocationGroupId", "OrganizationGroupId"):
                    v = result.get(field)
                    if isinstance(v, int):
                        new_id = v
                        break
            new_uuid = _extract_og_uuid(result)

        og_name = body.get("Name", "")
        if og_name and new_id and self._cached_og_name_map is not None:
            self._cached_og_name_map[og_name] = {"id": new_id, "uuid": new_uuid}
            log.info("OG '%s' created (id=%s) — added to name map", og_name, new_id)

        return result

    def create_smart_group(self, payload: dict) -> dict:
        """
        Create a smart group in this environment.

        Managing OG: translated via remap table (GroupId→match, then Name→match),
        falling back to name-map, then root.  Never overridden by LCA.

        OG criteria: translated the same way; entries whose UAT OG is not under
        the managing OG in UAT's hierarchy are silently dropped so WS1 accepts
        the payload without changing the managing OG.
        """
        og_map = self._build_og_name_map()
        id_info = self._build_og_id_info_map()
        tag_map = self._build_tag_name_map()
        root_og_id = self._get_root_og_id()
        root_og_uuid = self._get_root_og_uuid()

        # --- Resolve the managing OG ---
        # Use remap table (matched by GroupId then Name) first, then name-map,
        # then root as last resort.  Never override with LCA — the managing OG
        # must match the PROD intent; criteria OGs that don't fit are dropped below.
        managed_id, managed_uuid = self._resolve_og_id(
            payload.get("ManagedByOrganizationGroupId"),
            payload.get("ManagedByOrganizationGroupName"),
            og_map,
        )
        if not managed_id:
            managed_id = root_og_id
            managed_uuid = root_og_uuid
            managed_name = payload.get("ManagedByOrganizationGroupName")
            if managed_name:
                log.info("SG '%s': managing OG '%s' not found in UAT, using root",
                         payload.get("Name"), managed_name)

        # --- Remap OrganizationGroups criteria entries ---
        # Translate each entry via remap table → name fallback.
        # Skip any entry whose UAT OG is not under the managing OG — WS1 rejects
        # criteria OGs that sit outside the managing OG's subtree.
        def _is_under(child_id: int, ancestor_id: int) -> bool:
            current: Optional[int] = child_id
            seen: set = set()
            while current is not None and current not in seen:
                if current == ancestor_id:
                    return True
                seen.add(current)
                current = id_info.get(current, {}).get("parent_id")
            return False

        remapped_ogs: List[dict] = []
        for og_entry in payload.get("OrganizationGroups", []):
            uat_id, uat_uuid = self._resolve_og_id(
                og_entry.get("Id"), og_entry.get("Name"), og_map
            )
            if not uat_id:
                log.info("SG '%s': OG criteria '%s' not found in UAT — skipped",
                         payload.get("Name"), og_entry.get("Name"))
                continue
            if managed_id and not _is_under(uat_id, managed_id):
                log.info("SG '%s': OG criteria '%s' (UAT id %s) is not under managing OG %s — skipped",
                         payload.get("Name"), og_entry.get("Name"), uat_id, managed_id)
                continue
            remapped_ogs.append({
                "Id": str(uat_id),
                "Name": og_entry.get("Name", ""),
                "Uuid": uat_uuid or "",
            })

        # --- Remap Tags criteria entries ---
        remapped_tags: List[dict] = []
        for tag_entry in payload.get("Tags", []):
            name = tag_entry.get("Name")
            if name and name in tag_map:
                remapped_tags.append({"Id": str(tag_map[name]), "Name": name})
            else:
                log.info("SG '%s': tag '%s' not found in UAT — skipped",
                         payload.get("Name"), name)

        # --- Strip source-env IDs and count-only fields ---
        strip_keys = {
            "SmartGroupID", "SmartGroupUuid", "UUID", "Id",
            "ManagedByOrganizationGroupId", "ManagedByOrganizationGroupUuid",
            "ManagedByOrganizationGroupName",
            "DeviceAdditions", "DeviceExclusions",
            "UserAdditions", "UserExclusions",
            "OrganizationGroups", "Tags",
            "Devices", "Assignments", "Exclusions",
        }
        clean = {k: v for k, v in payload.items() if k not in strip_keys}

        # Inject remapped values
        clean["ManagedByOrganizationGroupId"] = int(managed_id)
        if managed_uuid:
            clean["ManagedByOrganizationGroupUuid"] = managed_uuid
        if remapped_ogs:
            clean["OrganizationGroups"] = remapped_ogs
        if remapped_tags:
            clean["Tags"] = remapped_tags

        # UserDevice/UserGroup with no user entries is invalid — downgrade to All
        criteria = clean.get("CriteriaType", "")
        if criteria in ("UserDevice", "UserGroup") and not clean.get("UserGroups"):
            clean["CriteriaType"] = "All"
            log.info("SG '%s': CriteriaType %s→All (no portable user criteria)",
                     clean.get("Name"), criteria)

        return self._post("/api/mdm/smartgroups", clean)

    def create_tag(self, payload: dict) -> dict:
        og_map = self._build_og_name_map()

        # Treat 0 as missing — WS1 returns "id : 0 not found" when OG ID is null/0.
        raw_og_id = payload.get("OrganizationGroupId")
        if raw_og_id == 0:
            raw_og_id = None

        # Translate PROD OG ID → UAT OG ID via remap table, then name, then root.
        uat_og_id, _ = self._resolve_og_id(
            raw_og_id,
            payload.get("OrganizationGroupName") or payload.get("LocationGroupName"),
            og_map,
        )
        if not uat_og_id:
            uat_og_id = self._get_root_og_id()
        if not uat_og_id:
            raise ValueError("Cannot determine OrganizationGroupId for tag creation — "
                             "check UAT connection and PROD OG remap")

        body = {
            "TagName": payload.get("TagName") or payload.get("Name") or payload.get("name", ""),
            "TagType": 1,
            "LocationGroupId": uat_og_id,
        }
        return self._post("/api/mdm/tags/addtag", body)

    def create_script(self, payload: dict) -> dict:
        og_uuid = self._get_root_og_uuid()
        strip_keys = {"script_uuid", "Uuid", "ScriptId", "Id",
                      "organization_group_uuid", "assignment_count"}
        clean = {k: v for k, v in payload.items() if k not in strip_keys}
        if og_uuid:
            clean["organization_group_uuid"] = og_uuid
        path = f"/api/mdm/groups/{og_uuid}/scripts" if og_uuid else "/api/mdm/scripts"
        return self._post(path, clean)

    def create_sensor(self, payload: dict) -> dict:
        og_uuid = self._get_root_og_uuid()
        strip_keys = {"uuid", "Uuid", "Id", "SensorId",
                      "organization_group_uuid", "assigned_smart_groups"}
        clean = {k: v for k, v in payload.items() if k not in strip_keys}
        if og_uuid:
            clean["organization_group_uuid"] = og_uuid
        return self._post("/api/mdm/devicesensors", clean)

    def create_compliance_policy(self, payload: dict) -> dict:
        strip_keys = {"PolicyId", "Id", "UUID", "Uuid", "CompliancePolicyId"}
        clean = {k: v for k, v in payload.items() if k not in strip_keys}
        return self._post("/api/mdm/compliancepolicies", clean)

    def create_profile(self, payload: dict) -> dict:
        """
        Create a profile in this environment using the platform-specific endpoint:
          POST /api/profiles/platforms/{platform}/create

        OG and Smart Group IDs are remapped from PROD to this env before posting.
        The full enriched profile detail JSON is posted as-is after ID substitution.
        """
        og_map = self._build_og_name_map()

        # --- Determine platform path ---
        platform_raw = payload.get("Platform") or payload.get("TargetDeviceType") or ""
        if not isinstance(platform_raw, str):
            platform_raw = str(platform_raw)
        platform_path = _PROFILE_PLATFORM_PATH.get(platform_raw.strip().lower())
        if not platform_path:
            raise ValueError(
                f"Unknown profile platform '{platform_raw}' — "
                f"cannot determine create endpoint. "
                f"Known platforms: {sorted(_PROFILE_PLATFORM_PATH.keys())}"
            )

        # --- Strip source-env identity fields ---
        strip_keys = {
            "ProfileId", "Uuid", "UUID",
            "AssignedDeviceCount", "AssignedGroupCount",
            "IsManaged", "DownloadUrl",
        }
        clean = {k: v for k, v in payload.items() if k not in strip_keys}

        # --- Remap OG ID ---
        # Try OrganizationGroupId then LocationGroupId; treat 0 as unset.
        raw_og_id = clean.get("OrganizationGroupId") or clean.get("LocationGroupId")
        if raw_og_id == 0:
            raw_og_id = None
        uat_og_id, _ = self._resolve_og_id(
            raw_og_id,
            payload.get("OrganizationGroupName") or payload.get("LocationGroupName"),
            og_map,
        )
        if not uat_og_id:
            uat_og_id = self._get_root_og_id()
        clean["OrganizationGroupId"] = uat_og_id
        clean.pop("LocationGroupId", None)

        # --- Remap Smart Group assignments ---
        # AssignedSmartGroups: list of {SmartGroupId, Name, ...}
        if "AssignedSmartGroups" in clean:
            remapped: List[dict] = []
            for entry in clean["AssignedSmartGroups"]:
                prod_sg_id = entry.get("SmartGroupId") or entry.get("Id")
                uat_sg_id = self._resolve_sg_id(prod_sg_id)
                if uat_sg_id:
                    remapped.append({**entry, "SmartGroupId": uat_sg_id, "Id": uat_sg_id})
                else:
                    log.info("Profile '%s': SG assignment id %s not mapped in UAT — skipped",
                             payload.get("ProfileName") or payload.get("Name"), prod_sg_id)
            clean["AssignedSmartGroups"] = remapped

        # SmartGroupIds: plain list of IDs (some API versions)
        if "SmartGroupIds" in clean:
            clean["SmartGroupIds"] = [
                self._resolve_sg_id(sid)
                for sid in clean["SmartGroupIds"]
                if self._resolve_sg_id(sid)
            ]

        # Build candidate endpoints — try both with and without /mdm/, and both the
        # normalised platform path and the raw Platform string from the payload, because
        # WS1 version/deployment differences make it impossible to know in advance which
        # variant the target server supports.
        candidate_endpoints: List[str] = []
        seen: set = set()
        for prefix in ("/api/mdm/profiles/platforms", "/api/profiles/platforms"):
            for seg in dict.fromkeys([platform_path, platform_raw.strip()]):  # dedup, order preserved
                if seg:
                    ep = f"{prefix}/{seg}/create"
                    if ep not in seen:
                        candidate_endpoints.append(ep)
                        seen.add(ep)

        last_exc: Optional[Exception] = None
        for ep in candidate_endpoints:
            try:
                return self._post(ep, clean)
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    last_exc = exc
                    log.debug("Profile create 404 on %s — trying next variant", ep)
                    continue
                raise  # non-404 error; surface immediately

        raise last_exc or ValueError(
            f"All profile create endpoints returned 404. Tried: {candidate_endpoints}"
        )

    def cleanup(self):
        if self._cert_files:
            for f in self._cert_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass


# ------------------------------------------------------------------ reference data

# Maps the Platform field value from a PROD profile to the WS1 API URL path segment
# used in POST /api/profiles/platforms/{path}/create.
_PROFILE_PLATFORM_PATH: Dict[str, str] = {
    # iOS / iPadOS
    "apple":            "apple_ios",
    "apple_ios":        "apple_ios",
    "ios":              "apple_ios",
    "ipad":             "apple_ios",
    "ipados":           "apple_ios",
    # macOS
    "apple_osx":        "apple_osx",
    "apple_macos":      "apple_osx",
    "macos":            "apple_osx",
    "osx":              "apple_osx",
    # Android
    "android":          "android",
    "androidwork":      "android",
    # Windows Desktop
    "win10":            "win10",
    "windows10":        "win10",
    "windows":          "win10",
    "winrt":            "win10",
    # Windows Phone / Legacy
    "winphone":         "winphone",
    "windowsphone":     "winphone",
    "wp8":              "winphone",
    # ChromeOS
    "chrome":           "Chrome",
    "chromeos":         "Chrome",
    # Linux
    "linux":            "linux",
}

# WS1 UEM built-in OG types that can be created via the standard API.
# Any LocationGroupType NOT in this set is a custom/non-standard type that must
# be manually registered in the target environment before OGs of that type can
# be created there.
STANDARD_OG_TYPES: set = {
    "Container",
    "Customer",
    "Division",
    "Global",
    "Partner",
    "Prospect",
    "Region",
    "User Defined",
    "UserDefined",   # API variant spelling
}

_OG_TYPE_DESC: Dict[str, str] = {
    "Customer":     "Tenant root — top-level customer organization",
    "Global":       "Global root — above all customers",
    "Container":    "Logical grouping container (no devices enrolled directly)",
    "Division":     "Functional division within a container",
    "Partner":      "Partner organization",
    "Prospect":     "Prospect organization",
    "Region":       "Regional grouping",
    "User Defined": "Custom type defined by the tenant admin",
    "UserDefined":  "Custom type defined by the tenant admin",
}
