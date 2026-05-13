import ast
import base64
import json
from pathlib import Path
from typing import Any


HEX_ID_ALPHABET = "0123456789ABCDEF"


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


def _encode_id_to_hex_digit(value: int) -> str:
    if value < 0 or value >= len(HEX_ID_ALPHABET):
        return "?"
    return HEX_ID_ALPHABET[value]


def _bin_prefix(value: int, prefix_len: int) -> str:
    return format(value, "08b")[:prefix_len]


def _extract_three_base64_ciphertexts(task_path: Path) -> list[bytes]:
    text = task_path.read_text(encoding="utf-8", errors="replace")

    # The file contains Python bytes literals like: b'....'
    # We parse them with ast.literal_eval for correctness.
    blobs: list[bytes] = []
    start = 0
    while True:
        b_index = text.find("b'", start)
        if b_index == -1:
            break
        end_index = text.find("'", b_index + 2)
        if end_index == -1:
            break

        # Heuristic: the base64 blob is huge; keep scanning until we hit the matching closing quote.
        # Since base64 doesn't contain single quotes, the first one after b' is the closing quote.
        token = text[b_index : end_index + 1]
        try:
            literal = ast.literal_eval(token)
        except Exception:
            start = end_index + 1
            continue

        if isinstance(literal, (bytes, bytearray)):
            blobs.append(bytes(literal))
            if len(blobs) == 3:
                return blobs
        start = end_index + 1

    raise ValueError(f"Expected 3 base64 ciphertexts in {task_path}, found {len(blobs)}")


def _load_and_number_xor_maps(xor_maps_path: Path) -> tuple[int, dict[str, int]]:
    data: dict[str, Any] = json.loads(xor_maps_path.read_text(encoding="utf-8"))
    prefix_len = int(data.get("bin_prefix_len", 2))

    mapping = data.get("xor_triplet_to_triples")
    if not isinstance(mapping, dict):
        raise ValueError("xor_triplet_to_triples must be a dict")

    # Support both formats:
    # - old: key -> list[triple]
    # - new: key -> {id: int, triples: list[triple]}
    needs_rewrite = False
    key_to_id: dict[str, int] = {}

    # Determine if already numbered
    already_numbered = True
    for value in mapping.values():
        if not (isinstance(value, dict) and "id" in value and "triples" in value):
            already_numbered = False
            break

    if already_numbered:
        ids_need_hex_rewrite = False
        for key, value in mapping.items():
            parsed_id = _parse_id(value["id"])  # type: ignore[index]
            key_to_id[key] = parsed_id
            if not (isinstance(value["id"], str) and value["id"].strip().upper() in HEX_ID_ALPHABET):
                ids_need_hex_rewrite = True

        if ids_need_hex_rewrite:
            new_mapping: dict[str, dict[str, Any]] = {}
            for key, value in mapping.items():
                xor_triplet_id = key_to_id[key]
                new_mapping[key] = {
                    "id": _encode_id_to_hex_digit(xor_triplet_id),
                    "triples": value["triples"],  # type: ignore[index]
                }
            data["xor_triplet_to_triples"] = new_mapping
            xor_maps_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        return prefix_len, key_to_id

    # Number deterministically by sorted key
    new_mapping: dict[str, dict[str, Any]] = {}
    for xor_triplet_id, xor_triplet_key in enumerate(sorted(mapping.keys())):
        triples = mapping[xor_triplet_key]
        new_mapping[xor_triplet_key] = {
            "id": _encode_id_to_hex_digit(xor_triplet_id),
            "triples": triples,
        }
        key_to_id[xor_triplet_key] = xor_triplet_id
        needs_rewrite = True

    if needs_rewrite:
        data["xor_triplet_to_triples"] = new_mapping
        xor_maps_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return prefix_len, key_to_id


def build_masks(
    ciphertexts: list[bytes],
    prefix_len: int,
    xor_triplet_key_to_id: dict[str, int],
) -> list[str]:
    if len(ciphertexts) != 3:
        raise ValueError("Expected exactly 3 ciphertexts")

    c1, c2, c3 = ciphertexts
    length = min(len(c1), len(c2), len(c3))

    mask1_chars: list[str] = []
    mask2_chars: list[str] = []
    mask3_chars: list[str] = []

    for i in range(length):
        b1, b2, b3 = c1[i], c2[i], c3[i]

        xor_ab = _bin_prefix(b1 ^ b2, prefix_len)
        xor_ac = _bin_prefix(b1 ^ b3, prefix_len)
        xor_bc = _bin_prefix(b2 ^ b3, prefix_len)
        xor_key = f"{xor_ab}|{xor_ac}|{xor_bc}"

        xor_id = xor_triplet_key_to_id.get(xor_key)
        ch = _encode_id_to_hex_digit(xor_id) if xor_id is not None else "?"

        out1 = ch
        out2 = ch
        out3 = ch

        # If any ciphertext bytes are equal, mark '&' in the masks
        # corresponding to those ciphertexts.
        if b1 == b2:
            out1 = "&"
            out2 = "&"
        if b1 == b3:
            out1 = "&"
            out3 = "&"
        if b2 == b3:
            out2 = "&"
            out3 = "&"

        mask1_chars.append(out1)
        mask2_chars.append(out2)
        mask3_chars.append(out3)

    return ["".join(mask1_chars), "".join(mask2_chars), "".join(mask3_chars)]


def main() -> None:
    k3_dir = Path(__file__).resolve().parent
    task_path = k3_dir / "2026_02_24_10_27_04_Анна_Казакевич_task.txt"
    xor_maps_path = k3_dir / "xor_maps3.json"

    base64_ciphertexts = _extract_three_base64_ciphertexts(task_path)
    ciphertexts = [base64.b64decode(blob) for blob in base64_ciphertexts]

    prefix_len, key_to_id = _load_and_number_xor_maps(xor_maps_path)

    masks = build_masks(ciphertexts, prefix_len, key_to_id)

    out_path = k3_dir / "mask3_final_3.txt"
    out_path.write_text("\n".join(masks), encoding="utf-8")

    print(f"loaded ciphertext bytes: {[len(c) for c in ciphertexts]}")
    print(f"mask length: {len(masks[0])}")
    print(f"saved: {out_path.name}")


if __name__ == "__main__":
    main()
