from PIL import Image


def to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def from_bits(bits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) == 8:
            out.append(int(chunk, 2))
    return bytes(out)


def max_payload_bytes(image_path: str) -> int:
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    capacity_bits = width * height * 3
    return max((capacity_bits - 32) // 8, 0)


def encode_lsb(image_path: str, message: str, output_path: str) -> None:
    img = Image.open(image_path).convert("RGB")
    pixels = bytearray(img.tobytes())

    payload = message.encode("utf-8")
    header = len(payload).to_bytes(4, byteorder="big")
    bits = to_bits(header + payload)

    if len(bits) > len(pixels):
        raise ValueError("Message is too large for this image")

    for i, bit in enumerate(bits):
        pixels[i] = (pixels[i] & 0xFE) | int(bit)

    encoded = Image.frombytes("RGB", img.size, bytes(pixels))
    encoded.save(output_path)


def decode_lsb(image_path: str) -> str:
    img = Image.open(image_path).convert("RGB")
    pixels = img.tobytes()

    header_bits = "".join(str(pixels[i] & 1) for i in range(32))
    message_len = int.from_bytes(from_bits(header_bits), byteorder="big")

    total_message_bits = message_len * 8
    message_bits = "".join(str(pixels[i] & 1) for i in range(32, 32 + total_message_bits))
    return from_bits(message_bits).decode("utf-8", errors="strict")


def main() -> None:
    image_path = "K6/original.png"
    output_path = "K6/encoded.png"
    message = "Тестовое сообщение для K6: информационная безопасность"

    print(f"\n=== K6: Image LSB ===")
    print(f"Capacity (bytes): {max_payload_bytes(image_path)}")
    encode_lsb(image_path, message, output_path)
    print(f"Encoded successfully: {output_path}")

    decoded = decode_lsb(output_path)
    print(f"Decoded message: {decoded}")
    print()


if __name__ == "__main__":
    main()
