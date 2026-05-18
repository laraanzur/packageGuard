import json
from datetime import datetime, timezone
from pathlib import Path
from urllib import request, error, parse

_MAX_DISTANCE = 2
_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "all_10k.json"


def _normalize_name(name):
    name = str(name or "").strip()
    if not name:
        return ""
    if name.startswith("@"):
        at_index = name.rfind("@")
        if at_index > 0 and "/" in name[:at_index]:
            name = name[:at_index]
    else:
        at_index = name.rfind("@")
        if at_index > 0:
            name = name[:at_index]
    return name.lower()


def _load_popular_list():
    if not _DATA_PATH.exists():
        return []

    with _DATA_PATH.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    entries = {}
    for item in data:
        if not isinstance(item, list) or not item:
            continue
        raw_name = str(item[0])
        key = _normalize_name(raw_name)
        if not key:
            continue
        if key not in entries:
            entries[key] = raw_name

    popular = []
    for key, value in entries.items():
        popular.append((key, value))

    return popular


def _edit_distance_limited(left, right, max_distance):
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1

    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        row_min = current[0]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current[j] = min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + cost,
            )
            if current[j] < row_min:
                row_min = current[j]
        if row_min > max_distance:
            return max_distance + 1
        previous = current

    return previous[-1]


def _fetch_json(url, timeout=6):
    try:
        with request.urlopen(url, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except (error.URLError, ValueError, TimeoutError):
        return None


def _fetch_metadata(name):
    encoded = parse.quote(name, safe="")
    registry = _fetch_json(f"https://registry.npmjs.org/{encoded}")
    downloads = _fetch_json(f"https://api.npmjs.org/downloads/point/last-week/{encoded}")

    created = None
    age_days = None
    modified = None
    days_since_modified = None
    if registry and isinstance(registry.get("time"), dict):
        created = registry["time"].get("created")
        modified = registry["time"].get("modified")

        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created_dt).days
            except ValueError:
                created = None
                age_days = None

        if modified:
            try:
                modified_dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                days_since_modified = (datetime.now(timezone.utc) - modified_dt).days
            except ValueError:
                modified = None
                days_since_modified = None

    downloads_last_week = None
    if downloads and isinstance(downloads.get("downloads"), int):
        downloads_last_week = downloads["downloads"]

    return {
        "age_days": age_days,
        "modified": modified,
        "days_since_modified": days_since_modified,
        "downloads_last_week": downloads_last_week,
    }


def evaluate_package_trust(name):
    normalized = _normalize_name(name)
    if not normalized:
        return None

    popular = _load_popular_list()
    best = None

    for candidate_key, candidate_name in popular:
        if candidate_key == normalized:
            best = {
                "match": candidate_name,
                "distance": 0,
            }
            break
        if abs(len(candidate_key) - len(normalized)) > _MAX_DISTANCE:
            continue
        distance = _edit_distance_limited(normalized, candidate_key, _MAX_DISTANCE)
        if distance > _MAX_DISTANCE:
            continue
        if best is None or distance < best["distance"]:
            best = {
                "match": candidate_name,
                "distance": distance,
            }

    metadata = _fetch_metadata(normalized)
    formatted_metadata = {}

    if best and best["distance"] == 0 and _normalize_name(best["match"]) == normalized:
        score = -2
        status = "exact"
        formatted_metadata["status"] = f"[OK] Package found in popular package database"
    elif best:
        score = 12
        status = "similar"
        formatted_metadata["status"] = f"[!!] Possible typosquating, package name is similar to popular package: {best["match"]}"
    else:
        score = 2
        status = "not found"
        formatted_metadata["status"] = f"[?] Package name not found in the popular package dataset"

    newPackageFlag = False

    age_days = metadata.get("age_days")
    if age_days is not None:
        if age_days < 1:
            score += 10
            formatted_metadata["age_days"] = f"[!!] Newly created package ({age_days} days)"
            newPackageFlag = True
        if age_days <= 30:
            score += 3
            formatted_metadata["age_days"] = f"[?] Recently created package ({age_days} days)"
        elif age_days >= 365:
            score -= 3
            formatted_metadata["age_days"] = f"[OK] Established package ({age_days} days)"
        else:
            formatted_metadata["age_days"] = f"[INFO] Package age: {age_days} days"

    downloads_last_week = metadata.get("downloads_last_week")
    if downloads_last_week is not None:
        if downloads_last_week <= 1000:
            score += 5
            formatted_metadata["downloads_last_week"] = f"[!] Very low weekly downloads ({downloads_last_week})"
        elif downloads_last_week <= 10000:
            score += 3
            formatted_metadata["downloads_last_week"] = f"[?] Low weekly downloads ({downloads_last_week})"
        elif downloads_last_week >= 30000:
            score -= 2
            formatted_metadata["downloads_last_week"] = f"[OK] High weekly downloads ({downloads_last_week})"
        else:
            formatted_metadata["downloads_last_week"] = f"[INFO] Weekly downloads: {downloads_last_week}"

    days_since_modified = metadata.get("days_since_modified")
    if days_since_modified is not None:
        if days_since_modified < 1:
            score += 10
            formatted_metadata["days_since_modified"] = f"[!!] Package modified today (0 days)"
            newPackageFlag = True
        elif days_since_modified >= 180:
            score += 2
            formatted_metadata["days_since_modified"] = f"[?] Package not updated in {days_since_modified} days"
        else:
            formatted_metadata["days_since_modified"] = f"[OK] Package is regularly updated"
    

    if score >= 10:
        risk = "high"
    elif score >= 5:
        risk = "medium"
    elif score >= 0:
        risk = "low"
    else:
        risk = "clean"

    return {
        "name": normalized,
        "status": status,
        "risk": risk,
        "match": best["match"] if best else None,
        "distance": best["distance"] if best else None,
        "metadata": formatted_metadata,
        "new_package": newPackageFlag
    }
