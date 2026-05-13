import json
from pathlib import Path

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


def evaluate_typosquatting(name):
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
	
	if not best:
		return {
			"name": normalized,
			"status": "none",
			"risk": "clean",
		}

	if best["distance"] == 0 and _normalize_name(best["match"]) == normalized:
		return {
			"name": normalized,
			"status": "exact",
			"risk": "clean",
			"match": best["match"],
		}

	return {
		"name": normalized,
		"status": "similar",
		"risk": "high",
		"match": best["match"],
		"distance": best["distance"],
	}
