import json
from pathlib import Path


symbols = " aA"
BIN_PREFIX_LEN = 3
HEX_ID_ALPHABET = "0123456789ABCDEF"


def to_bin_str(value: int, width: int = 8) -> str:
    return format(value, f"0{width}b")


def _parse_id(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Empty id")
        if text.isdigit():
            return int(text, 10)
        return int(text, 16)
    raise TypeError(f"Unsupported id type: {type(value)!r}")


def _id_to_hex_digit(value: int) -> str:
    if value < 0 or value >= len(HEX_ID_ALPHABET):
        raise ValueError(f"id {value} does not fit into a single hex digit")
    return HEX_ID_ALPHABET[value]


def build_xor_maps_3(
    symbols_str: str,
) -> tuple[dict[str, dict[str, str]], dict[str, list[list[str]]]]:
    triple_to_pairwise_xor_bin: dict[str, dict[str, str]] = {}
    xor_triplet_to_triples: dict[str, list[list[str]]] = {}

    for first_index in range(len(symbols_str)):
        for second_index in range(len(symbols_str)):
            for third_index in range(len(symbols_str)):
                first_char = symbols_str[first_index]
                second_char = symbols_str[second_index]
                third_char = symbols_str[third_index]

                triple_key = f"{repr(first_char)}|{repr(second_char)}|{repr(third_char)}"

                xor_ab = to_bin_str(ord(first_char) ^ ord(second_char))[:BIN_PREFIX_LEN]
                xor_ac = to_bin_str(ord(first_char) ^ ord(third_char))[:BIN_PREFIX_LEN]
                xor_bc = to_bin_str(ord(second_char) ^ ord(third_char))[:BIN_PREFIX_LEN]

                xor_triplet_key = f"{xor_ab}|{xor_ac}|{xor_bc}"

                triple_to_pairwise_xor_bin[triple_key] = {
                    "triple": [first_char, second_char, third_char],
                    "ab": xor_ab,
                    "ac": xor_ac,
                    "bc": xor_bc,
                    "key": xor_triplet_key,
                }

                xor_triplet_to_triples.setdefault(xor_triplet_key, []).append(
                    [first_char, second_char, third_char]
                )

    return triple_to_pairwise_xor_bin, xor_triplet_to_triples


def _load_existing_key_ids(xor_maps_path: Path) -> dict[str, int]:
    if not xor_maps_path.exists():
        return {}

    data = json.loads(xor_maps_path.read_text(encoding="utf-8"))
    mapping = data.get("xor_triplet_to_triples")
    if not isinstance(mapping, dict):
        return {}

    key_to_id: dict[str, int] = {}
    for key, value in mapping.items():
        if isinstance(value, dict) and "id" in value:
            try:
                key_to_id[key] = _parse_id(value["id"])
            except Exception:
                continue

    # Only keep unique ids; if the file is malformed, prefer safety.
    if len(set(key_to_id.values())) != len(key_to_id):
        return {}

    return key_to_id


def _xor_triplet_key_for_triple(triple: list[str], prefix_len: int) -> str:
    if len(triple) != 3:
        raise ValueError("Expected triple of length 3")

    a, b, c = triple
    xor_ab = to_bin_str(ord(a) ^ ord(b))[:prefix_len]
    xor_ac = to_bin_str(ord(a) ^ ord(c))[:prefix_len]
    xor_bc = to_bin_str(ord(b) ^ ord(c))[:prefix_len]
    return f"{xor_ab}|{xor_ac}|{xor_bc}"


def _load_old_ids_translated_to_new_keys(
    xor_maps_path: Path, new_prefix_len: int
) -> dict[str, int]:
    """Translate ids from an older xor_maps file into the current key space.

    We use the triples list for each old key, recompute the xor-triplet key
    with the new prefix length, and require it to be unambiguous.
    """
    if not xor_maps_path.exists():
        return {}

    data = json.loads(xor_maps_path.read_text(encoding="utf-8"))
    mapping = data.get("xor_triplet_to_triples")
    if not isinstance(mapping, dict):
        return {}

    translated: dict[str, int] = {}
    used_old_ids: set[int] = set()

    for _old_key, value in mapping.items():
        if not (isinstance(value, dict) and "id" in value and "triples" in value):
            continue
        try:
            old_id = _parse_id(value["id"])
        except Exception:
            continue

        triples = value.get("triples")
        if not isinstance(triples, list) or not triples:
            continue

        new_keys: set[str] = set()
        for triple in triples:
            if not (isinstance(triple, list) and all(isinstance(x, str) for x in triple)):
                continue
            new_keys.add(_xor_triplet_key_for_triple(triple, new_prefix_len))

        if len(new_keys) != 1:
            # Ambiguous translation (or malformed data). Skip to avoid collisions.
            continue

        (new_key,) = tuple(new_keys)
        if new_key in translated and translated[new_key] != old_id:
            continue
        if old_id in used_old_ids and translated.get(new_key) != old_id:
            continue

        translated[new_key] = old_id
        used_old_ids.add(old_id)

    return translated


def main() -> None:
    triple_to_pairwise_xor_bin, xor_triplet_to_triples = build_xor_maps_3(symbols)

    # Preserve numbering for keys that already exist in xor_maps3.json
    k3_dir = Path(__file__).resolve().parent
    old_maps_path = k3_dir / "xor_maps3.json"
    old_key_to_id = _load_existing_key_ids(old_maps_path)
    translated_old_ids = _load_old_ids_translated_to_new_keys(old_maps_path, BIN_PREFIX_LEN)

    xor_triplet_to_triples_numbered: dict[str, dict[str, object]] = {}
    preserved_ids = set(old_key_to_id.values()) | set(translated_old_ids.values())
    next_id = (max(preserved_ids) + 1) if preserved_ids else 0

    for xor_triplet_key in sorted(xor_triplet_to_triples.keys()):
        if xor_triplet_key in translated_old_ids:
            xor_triplet_id = translated_old_ids[xor_triplet_key]
        elif xor_triplet_key in old_key_to_id:
            xor_triplet_id = old_key_to_id[xor_triplet_key]
        else:
            xor_triplet_id = next_id
            next_id += 1

        xor_triplet_to_triples_numbered[xor_triplet_key] = {
            "id": _id_to_hex_digit(xor_triplet_id),
            "triples": xor_triplet_to_triples[xor_triplet_key],
        }

    output = {
        "symbols": symbols,
        "symbols_len": len(symbols),
        "bin_prefix_len": BIN_PREFIX_LEN,
        #"triple_to_pairwise_xor_bin": triple_to_pairwise_xor_bin,
        "xor_triplet_to_triples": xor_triplet_to_triples_numbered,
    }

    out_path = Path(__file__).with_name("xor_maps4.json")
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"symbols: {len(symbols)}")
    print(f"triples: {len(triple_to_pairwise_xor_bin)}")
    if translated_old_ids:
        print(f"preserved ids translated from xor_maps3.json: {len(translated_old_ids)}")
    print(f"saved: {out_path}")


if __name__ == "__main__":
    main()